CXX ?= clang++
CXXFLAGS ?= -std=c++20 -Wall -Wextra -pedantic

TARGETS := computer_id_probe commpage_time_probe time_watchdog_crc32 time_watchdog_crc32_tests

.PHONY: all clean test integration-test controlled-integration-test

all: $(TARGETS)

computer_id_probe: computer_id_probe.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

commpage_time_probe: commpage_time_probe.cpp
	$(CXX) $(CXXFLAGS) -x objective-c++ -framework Foundation $< -o $@ -lz

time_watchdog_crc32: time_watchdog_crc32.cpp
	$(CXX) $(CXXFLAGS) -x objective-c++ -framework Foundation $< -o $@ -lz

time_watchdog_crc32_tests: CXXFLAGS += -Wno-unused-function -Wno-nullability-completeness
time_watchdog_crc32_tests: time_watchdog_crc32_tests.cpp
	$(CXX) $(CXXFLAGS) -x objective-c++ -framework Foundation $< -o $@ -lz

test: time_watchdog_crc32_tests
	./time_watchdog_crc32_tests

integration-test: time_watchdog_crc32
	python3 ./time_watchdog_crc32_integration_tests.py

controlled-integration-test: time_watchdog_crc32
	python3 ./time_watchdog_crc32_controlled_integration_tests.py

clean:
	rm -f $(TARGETS)