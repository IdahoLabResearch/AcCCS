# AcCCS Makefile
# This Makefile simply calls the Makefile in the EXPy project

EXPY_DIR = external_libs/EXPy

# Default target
all:
	$(MAKE) -C $(EXPY_DIR) all

# Clean target
clean:
	$(MAKE) -C $(EXPY_DIR) clean

# Pass through any other targets to the EXPy Makefile
%:
	$(MAKE) -C $(EXPY_DIR) $@

.PHONY: all clean