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
include test/CMakeFiles/test_fbx.dir/depend.make

# Include the progress variables for this target.
include test/CMakeFiles/test_fbx.dir/progress.make

# Include the compile flags for this target's objects.
include test/CMakeFiles/test_fbx.dir/flags.make

test/CMakeFiles/test_fbx.dir/test_fbx.c.o: test/CMakeFiles/test_fbx.dir/flags.make
test/CMakeFiles/test_fbx.dir/test_fbx.c.o: /home/mbonjour/RELIC/relic/test/test_fbx.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/RELIC/relic-target-bls48/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object test/CMakeFiles/test_fbx.dir/test_fbx.c.o"
	cd /home/mbonjour/RELIC/relic-target-bls48/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_fbx.dir/test_fbx.c.o   -c /home/mbonjour/RELIC/relic/test/test_fbx.c

test/CMakeFiles/test_fbx.dir/test_fbx.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_fbx.dir/test_fbx.c.i"
	cd /home/mbonjour/RELIC/relic-target-bls48/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/RELIC/relic/test/test_fbx.c > CMakeFiles/test_fbx.dir/test_fbx.c.i

test/CMakeFiles/test_fbx.dir/test_fbx.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_fbx.dir/test_fbx.c.s"
	cd /home/mbonjour/RELIC/relic-target-bls48/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/RELIC/relic/test/test_fbx.c -o CMakeFiles/test_fbx.dir/test_fbx.c.s

# Object files for target test_fbx
test_fbx_OBJECTS = \
"CMakeFiles/test_fbx.dir/test_fbx.c.o"

# External object files for target test_fbx
test_fbx_EXTERNAL_OBJECTS =

bin/test_fbx: test/CMakeFiles/test_fbx.dir/test_fbx.c.o
bin/test_fbx: test/CMakeFiles/test_fbx.dir/build.make
bin/test_fbx: lib/librelic_s.a
bin/test_fbx: /usr/lib/libgmp.so
bin/test_fbx: test/CMakeFiles/test_fbx.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mbonjour/RELIC/relic-target-bls48/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ../bin/test_fbx"
	cd /home/mbonjour/RELIC/relic-target-bls48/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_fbx.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
test/CMakeFiles/test_fbx.dir/build: bin/test_fbx

.PHONY : test/CMakeFiles/test_fbx.dir/build

test/CMakeFiles/test_fbx.dir/clean:
	cd /home/mbonjour/RELIC/relic-target-bls48/test && $(CMAKE_COMMAND) -P CMakeFiles/test_fbx.dir/cmake_clean.cmake
.PHONY : test/CMakeFiles/test_fbx.dir/clean

test/CMakeFiles/test_fbx.dir/depend:
	cd /home/mbonjour/RELIC/relic-target-bls48 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mbonjour/RELIC/relic /home/mbonjour/RELIC/relic/test /home/mbonjour/RELIC/relic-target-bls48 /home/mbonjour/RELIC/relic-target-bls48/test /home/mbonjour/RELIC/relic-target-bls48/test/CMakeFiles/test_fbx.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : test/CMakeFiles/test_fbx.dir/depend

