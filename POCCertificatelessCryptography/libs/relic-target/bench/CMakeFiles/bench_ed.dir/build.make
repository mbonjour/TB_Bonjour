# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/mbonjour/RELIC/relic

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mbonjour/RELIC/relic-target-bls48

# Include any dependencies generated for this target.
include bench/CMakeFiles/bench_ed.dir/depend.make

# Include the progress variables for this target.
include bench/CMakeFiles/bench_ed.dir/progress.make

# Include the compile flags for this target's objects.
include bench/CMakeFiles/bench_ed.dir/flags.make

bench/CMakeFiles/bench_ed.dir/bench_ed.c.o: bench/CMakeFiles/bench_ed.dir/flags.make
bench/CMakeFiles/bench_ed.dir/bench_ed.c.o: /home/mbonjour/RELIC/relic/bench/bench_ed.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/RELIC/relic-target-bls48/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object bench/CMakeFiles/bench_ed.dir/bench_ed.c.o"
	cd /home/mbonjour/RELIC/relic-target-bls48/bench && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bench_ed.dir/bench_ed.c.o   -c /home/mbonjour/RELIC/relic/bench/bench_ed.c

bench/CMakeFiles/bench_ed.dir/bench_ed.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bench_ed.dir/bench_ed.c.i"
	cd /home/mbonjour/RELIC/relic-target-bls48/bench && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/RELIC/relic/bench/bench_ed.c > CMakeFiles/bench_ed.dir/bench_ed.c.i

bench/CMakeFiles/bench_ed.dir/bench_ed.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bench_ed.dir/bench_ed.c.s"
	cd /home/mbonjour/RELIC/relic-target-bls48/bench && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/RELIC/relic/bench/bench_ed.c -o CMakeFiles/bench_ed.dir/bench_ed.c.s

# Object files for target bench_ed
bench_ed_OBJECTS = \
"CMakeFiles/bench_ed.dir/bench_ed.c.o"

# External object files for target bench_ed
bench_ed_EXTERNAL_OBJECTS =

bin/bench_ed: bench/CMakeFiles/bench_ed.dir/bench_ed.c.o
bin/bench_ed: bench/CMakeFiles/bench_ed.dir/build.make
bin/bench_ed: lib/librelic_s.a
bin/bench_ed: /usr/lib/libgmp.so
bin/bench_ed: bench/CMakeFiles/bench_ed.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mbonjour/RELIC/relic-target-bls48/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ../bin/bench_ed"
	cd /home/mbonjour/RELIC/relic-target-bls48/bench && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bench_ed.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
bench/CMakeFiles/bench_ed.dir/build: bin/bench_ed

.PHONY : bench/CMakeFiles/bench_ed.dir/build

bench/CMakeFiles/bench_ed.dir/clean:
	cd /home/mbonjour/RELIC/relic-target-bls48/bench && $(CMAKE_COMMAND) -P CMakeFiles/bench_ed.dir/cmake_clean.cmake
.PHONY : bench/CMakeFiles/bench_ed.dir/clean

bench/CMakeFiles/bench_ed.dir/depend:
	cd /home/mbonjour/RELIC/relic-target-bls48 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mbonjour/RELIC/relic /home/mbonjour/RELIC/relic/bench /home/mbonjour/RELIC/relic-target-bls48 /home/mbonjour/RELIC/relic-target-bls48/bench /home/mbonjour/RELIC/relic-target-bls48/bench/CMakeFiles/bench_ed.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : bench/CMakeFiles/bench_ed.dir/depend

