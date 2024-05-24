// Copyright 2023 Outreach Corporation. All Rights Reserved.
//
// Description: Defines logger singleton.
package cli

import (
	"log/slog"

	"github.com/getoutreach/gobox/pkg/olog"
)

// logger - a package level singleton *slog.Logger instance.
//
// Uses a combination of built-in slog and olog functionality to
// provide a standard, structured logging interface and implementation.
// *slog.Logger instance are concurrency safe.
var log *slog.Logger = olog.New()
