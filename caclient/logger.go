package caclient

import (
	"log"

	"github.com/stc-community/stc-dpki-casdk/pkg/logger"
	"go.uber.org/zap"
)

func init() {
	f := zap.RedirectStdLog(logger.S().Desugar())
	f()
	log.SetFlags(log.LstdFlags)
}
