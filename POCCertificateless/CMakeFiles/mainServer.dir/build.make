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
CMAKE_COMMAND = /home/mbonjour/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/202.6397.106/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/mbonjour/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/202.6397.106/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless

# Include any dependencies generated for this target.
include CMakeFiles/mainServer.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/mainServer.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/mainServer.dir/flags.make

CMakeFiles/mainServer.dir/server/mainServer.c.o: CMakeFiles/mainServer.dir/flags.make
CMakeFiles/mainServer.dir/server/mainServer.c.o: server/mainServer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/mainServer.dir/server/mainServer.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainServer.dir/server/mainServer.c.o   -c /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/server/mainServer.c

CMakeFiles/mainServer.dir/server/mainServer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainServer.dir/server/mainServer.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/server/mainServer.c > CMakeFiles/mainServer.dir/server/mainServer.c.i

CMakeFiles/mainServer.dir/server/mainServer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainServer.dir/server/mainServer.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/server/mainServer.c -o CMakeFiles/mainServer.dir/server/mainServer.c.s

CMakeFiles/mainServer.dir/cipherPOC.c.o: CMakeFiles/mainServer.dir/flags.make
CMakeFiles/mainServer.dir/cipherPOC.c.o: cipherPOC.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/mainServer.dir/cipherPOC.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainServer.dir/cipherPOC.c.o   -c /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/cipherPOC.c

CMakeFiles/mainServer.dir/cipherPOC.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainServer.dir/cipherPOC.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/cipherPOC.c > CMakeFiles/mainServer.dir/cipherPOC.c.i

CMakeFiles/mainServer.dir/cipherPOC.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainServer.dir/cipherPOC.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/cipherPOC.c -o CMakeFiles/mainServer.dir/cipherPOC.c.s

CMakeFiles/mainServer.dir/signaturePOC.c.o: CMakeFiles/mainServer.dir/flags.make
CMakeFiles/mainServer.dir/signaturePOC.c.o: signaturePOC.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/mainServer.dir/signaturePOC.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainServer.dir/signaturePOC.c.o   -c /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/signaturePOC.c

CMakeFiles/mainServer.dir/signaturePOC.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainServer.dir/signaturePOC.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/signaturePOC.c > CMakeFiles/mainServer.dir/signaturePOC.c.i

CMakeFiles/mainServer.dir/signaturePOC.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainServer.dir/signaturePOC.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/signaturePOC.c -o CMakeFiles/mainServer.dir/signaturePOC.c.s

CMakeFiles/mainServer.dir/utils/base64.c.o: CMakeFiles/mainServer.dir/flags.make
CMakeFiles/mainServer.dir/utils/base64.c.o: utils/base64.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/mainServer.dir/utils/base64.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainServer.dir/utils/base64.c.o   -c /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/utils/base64.c

CMakeFiles/mainServer.dir/utils/base64.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainServer.dir/utils/base64.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/utils/base64.c > CMakeFiles/mainServer.dir/utils/base64.c.i

CMakeFiles/mainServer.dir/utils/base64.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainServer.dir/utils/base64.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/utils/base64.c -o CMakeFiles/mainServer.dir/utils/base64.c.s

CMakeFiles/mainServer.dir/utils/socketUtils.c.o: CMakeFiles/mainServer.dir/flags.make
CMakeFiles/mainServer.dir/utils/socketUtils.c.o: utils/socketUtils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/mainServer.dir/utils/socketUtils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainServer.dir/utils/socketUtils.c.o   -c /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/utils/socketUtils.c

CMakeFiles/mainServer.dir/utils/socketUtils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainServer.dir/utils/socketUtils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/utils/socketUtils.c > CMakeFiles/mainServer.dir/utils/socketUtils.c.i

CMakeFiles/mainServer.dir/utils/socketUtils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainServer.dir/utils/socketUtils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/utils/socketUtils.c -o CMakeFiles/mainServer.dir/utils/socketUtils.c.s

# Object files for target mainServer
mainServer_OBJECTS = \
"CMakeFiles/mainServer.dir/server/mainServer.c.o" \
"CMakeFiles/mainServer.dir/cipherPOC.c.o" \
"CMakeFiles/mainServer.dir/signaturePOC.c.o" \
"CMakeFiles/mainServer.dir/utils/base64.c.o" \
"CMakeFiles/mainServer.dir/utils/socketUtils.c.o"

# External object files for target mainServer
mainServer_EXTERNAL_OBJECTS =

mainServer: CMakeFiles/mainServer.dir/server/mainServer.c.o
mainServer: CMakeFiles/mainServer.dir/cipherPOC.c.o
mainServer: CMakeFiles/mainServer.dir/signaturePOC.c.o
mainServer: CMakeFiles/mainServer.dir/utils/base64.c.o
mainServer: CMakeFiles/mainServer.dir/utils/socketUtils.c.o
mainServer: CMakeFiles/mainServer.dir/build.make
mainServer: libs/relic-target/lib/librelic.so
mainServer: libs/unqlite/libunqlite.a
mainServer: libs/binn/libbinn.so.3.0
mainServer: CMakeFiles/mainServer.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C executable mainServer"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/mainServer.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/mainServer.dir/build: mainServer

.PHONY : CMakeFiles/mainServer.dir/build

CMakeFiles/mainServer.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/mainServer.dir/cmake_clean.cmake
.PHONY : CMakeFiles/mainServer.dir/clean

CMakeFiles/mainServer.dir/depend:
	cd /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless /home/mbonjour/Desktop/TB_Bonjour/POCCertificateless/CMakeFiles/mainServer.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/mainServer.dir/depend

