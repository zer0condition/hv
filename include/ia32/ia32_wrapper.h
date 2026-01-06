#pragma once

/* avoid macro redefinition warnings from kernel apic headers */
#ifdef APIC_ID
#undef APIC_ID
#endif
#ifdef APIC_EOI
#undef APIC_EOI
#endif

#include "ia32.h"