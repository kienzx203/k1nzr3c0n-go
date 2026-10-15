package api

import (
	"strconv"
	"time"

	"k1nzr3c0n/internal/schedule"
)

func cronValid(expr string) bool { return schedule.Valid(expr) }

func cronNext(expr string) time.Time { return schedule.NextAfter(expr, time.Now()) }

func parseID(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }
