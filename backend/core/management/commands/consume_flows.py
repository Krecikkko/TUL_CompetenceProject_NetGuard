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

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from core.models import NetworkFlow

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Consume normalized network flows from Kafka and save them to the database."

    TOPIC = "flows.normalized"
    BOOTSTRAP_SERVERS = os.getenv(
        "KAFKA_BOOTSTRAP_SERVERS",
        "kafka:9092",
    ).split(",")
    
    GROUP_ID = "netguard-flow-consumer"

    DEFAULT_BATCH_SIZE = 500

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
            / "flow-event.v1.schema.json"
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
                        flow = self.deserialize_event(message.value)
                        batch.append(flow)

                    except (ValidationError, ValueError, TypeError) as ex:
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

        self.validator.validate(event)

        start_time = datetime.fromisoformat(
            event["start_time"]
        )

        # if timezone.is_naive(start_time):
        #     raise ValueError("start_time must include a timezone")

        # FlowEvent duration is milliseconds.
        # Django DurationField expects a timedelta.
        duration = timedelta(
            microseconds=round(event["duration_ms"] * 1000)
        )

        return NetworkFlow(
            start_timestamp_us=start_time,
            duration_us=duration,
            source_ip=event["src_ip"],
            source_port=event["src_port"],
            destination_ip=event["dst_ip"],
            destination_port=event["dst_port"],
            protocol=event["protocol"],
            packet_count=event["packets"],
            byte_count=event["bytes"],
            tcp_flags=event["tcp_flags"],
        )

    def save_batch(self, batch):
        with transaction.atomic():
            NetworkFlow.objects.bulk_create(
                batch,
                batch_size=self.batch_size,
            )

        logger.info("Saved %d network flows.", len(batch))
