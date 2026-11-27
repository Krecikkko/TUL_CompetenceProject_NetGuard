import json
import logging
import os
import signal
import time

from datetime import datetime, timedelta
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import DatabaseError, transaction
from django.conf import settings
from django.db.models import F, ExpressionWrapper, DateTimeField

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from core.models import NetworkFlow, TimeWindow, WindowFlow, Detection

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Consume Kafka detection events and persist detections with their flows."

    TOPIC = "detections.created"
    BOOTSTRAP_SERVERS = os.getenv(
        "KAFKA_BOOTSTRAP_SERVERS",
        "kafka:9092",
    ).split(",")
    
    GROUP_ID = "netguard-detection-consumer"

    DEFAULT_BATCH_SIZE = 100

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=self.DEFAULT_BATCH_SIZE,
            help="Number of events processed in one database transaction.",
        )
        parser.add_argument(
            "--auto-offset-reset",
            choices=["earliest", "latest"],
            default="earliest",
            help="Where to start when no committed offset exists.",
        )

    def handle(self, *args, **options):
        # input validation
        self.batch_size = options["batch_size"]

        if self.batch_size < 1:
            raise ValueError("--batch-size must be greater than zero")

        # command exec control
        self.running = True
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

        # validator
        self.validator = self.load_schema()

        # kafka init
        consumer = KafkaConsumer(
            self.TOPIC,
            bootstrap_servers=self.BOOTSTRAP_SERVERS,
            group_id=self.GROUP_ID,
            enable_auto_commit=False,
            auto_offset_reset=options["auto_offset_reset"],
            value_deserializer=lambda value: json.loads(
                value.decode("utf-8")
            ),
            consumer_timeout_ms=1000,
            max_poll_records=self.batch_size,
        )

        logger.info(f"Consuming Kafka topic '{self.TOPIC}' from {self.BOOTSTRAP_SERVERS}")

        # calling consume & error handling
        try:
            self.consume(consumer)
        except KafkaError:
            logger.exception("Kafka consumer error")
            raise
        finally:
            consumer.close()
            logger.info("Kafka consumer stopped.")

    def stop(self, signum, frame):
        logger.info("Shutdown signal received.")
        self.running = False

    def load_schema(self):
        schema_path = (
            Path("/contracts")
            / "kafka"
            / "detection-event.v1.schema.json"
        )

        with schema_path.open("r", encoding="utf-8") as schema_file:
            schema = json.load(schema_file)

        Draft202012Validator.check_schema(schema)

        return Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

    def consume(self, consumer: KafkaConsumer):
        while self.running:
            records = consumer.poll(
                timeout_ms=1000,
                max_records=self.batch_size,
            )

            if not records:
                continue

            batch = []

            # process records in partition/offset order
            for partition_records in records.values():
                for message in partition_records:
                    try:
                        detection_event = self.deserialize_event(message.value)
                        batch.append(detection_event)

                    except (
                        ValidationError,
                        ValueError,
                        TypeError,
                        KeyError,
                    ) as ex:
                        logger.error(
                            "Invalid Kafka message. Topic=%s Partition=%s "
                            "Offset=%s Error=%s",
                            message.topic,
                            message.partition,
                            message.offset,
                            ex,
                        )

            # Persist valid events and commit offsets only after
            # the database transaction succeeds.
            try:
                if batch:
                    self.save_batch(batch)

                consumer.commit()

            except DatabaseError:
                logger.exception(
                    "Database error while processing Kafka batch. "
                    "Offsets will not be committed."
                )
                time.sleep(2)

            except KafkaError:
                logger.exception("Failed to commit Kafka offsets.")
                raise

    def deserialize_event(self, event):
        if not isinstance(event, dict):
            raise ValueError("Kafka event must be a JSON object")

        # self.validator.validate(event)

        # detected_at = datetime.fromisoformat(
        #     event["timestamp"]
        # )

        # jeden to timestamp a 2. to iso bruh

        detected_at = datetime.fromtimestamp(
            float(event["timestamp"])
        )

        window_start = datetime.fromisoformat(
            event["window_start"]
        )

        duration = timedelta(
            seconds=event["duration_seconds"]
        )

        return {
            "method": event["method"],
            "rule_id": event["rule_id"],
            "detected_at_us": detected_at,
            "type": event["type"],
            "severity": event["severity"],
            "confidence": event["confidence"],
            "source_ip": event["src_ip"],
            "destination_ip": event["dst_ip"],
            "key_feature_values": {
                feature["name"]: feature["value"]
                for feature in event["features"]
            },
            "explanation": event["explanation"],
            "window_start": window_start,
            "duration": duration,
        }

    def save_batch(self, batch):
        with transaction.atomic():
            for event in batch:
                window_start = event["window_start"]
                duration = event["duration"]
                window_end = window_start + duration

                # determining window type
                window_type = None

                if event["source_ip"] is None and event["destination_ip"] is None:
                    window_type = TimeWindow.WindowType.GLOBAL
                elif event["source_ip"] is None:
                    window_type = TimeWindow.WindowType.DESTIN
                elif event["destination_ip"] is None:
                    window_type = TimeWindow.WindowType.SOURCE
                else:
                    window_type = TimeWindow.WindowType.SO1DE1

                # dynamic filters
                flow_filters = {
                    "start_timestamp_us__range": (window_start, window_end)
                }

                if window_type in (
                    TimeWindow.WindowType.SOURCE,
                    TimeWindow.WindowType.SO1DE1,
                ):
                    flow_filters["source_ip"] = event["source_ip"]

                if window_type in (
                    TimeWindow.WindowType.DESTIN,
                    TimeWindow.WindowType.SO1DE1,
                ):
                    flow_filters["destination_ip"] = event["destination_ip"]

                # finding flows that overlap with window
                candidate_flows = (
                    NetworkFlow.objects
                    .filter(**flow_filters)
                    .annotate(
                        end_timestamp_us=ExpressionWrapper(
                            F("start_timestamp_us") + F("duration_us"),
                            output_field=DateTimeField(),
                        )
                    ).filter(
                        end_timestamp_us__range=(window_start, window_end),
                    )
                )

                # creating window
                window = TimeWindow.objects.create(
                    start_timestamp_us=window_start,
                    duration_us=duration,
                    type=window_type,
                )

                # assigning flows to window
                flows = list(candidate_flows)

                if flows:
                    WindowFlow.objects.bulk_create(
                        [
                            WindowFlow(
                                window=window,
                                flow=flow,
                            )
                            for flow in flows
                        ],
                        batch_size=self.batch_size,
                        ignore_conflicts=True,
                    )

                # creating detection and assigning window
                Detection.objects.create(
                    method=event["method"],
                    rule_id=event["rule_id"],
                    detected_at_us=event["detected_at_us"],
                    type=event["type"],
                    severity=event["severity"],
                    confidence=event["confidence"],
                    source_ip=event["source_ip"],
                    destination_ip=event["destination_ip"],
                    key_feature_values=event["key_feature_values"],
                    explanation=event["explanation"],
                    window=window,
                )

                # log
                logger.info(
                    "Saved detection. Rule=%s Type=%s Severity=%s Window=%s Flows=%d",
                    event["rule_id"],
                    event["type"],
                    event["severity"],
                    window.id,
                    len(flows),
                )

        logger.info("Saved %d detections.", len(batch))
        