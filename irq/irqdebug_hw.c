#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/hw_breakpoint.h>

#include "debug_log.h"

#define IRQ_DEBUG_HW_BREAKPOINT_ROOT_DIR "irqhw_breakpoints"
