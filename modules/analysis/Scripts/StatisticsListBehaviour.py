import math
from collections import deque

class ZScoreBehaviour:

    def __init__(self):
        self.mem = deque()
        self.n = 0
        self.total_sum = 0
        self.sum_sq = 0

    def Add(self, x: int) -> None:
        #Modifies an existing item x -> x + 1
        self.mem.append(x)
        self.n += 1
        self.total_sum += x
        self.sum_sq += x*x

    def Low(self) -> None:
        x = self.mem.popleft()
        self.n -= 1
        self.total_sum -= x
        self.sum_sq -= x*x

    def CalcMean(self) -> float:
        if self.n == 0:
            return 0.0
        return self.total_sum / self.n

    def CalcDev(self, ddof: int = 1) -> float:
        if self.n <= ddof:
            return 0.0
        numerator = self.n * self.sum_sq - self.total_sum * self.total_sum
        variance = numerator / (self.n * (self.n - ddof))
        return math.sqrt(max(0.0, variance))

    def CalcZScore(self,value:int) -> float:
        deviation = self.CalcDev()
        if deviation == 0:
            return 0.0
        return (value - self.CalcMean()) / deviation
