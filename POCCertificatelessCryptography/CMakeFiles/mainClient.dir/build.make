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
CMAKE_SOURCE_DIR = /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography

# Include any dependencies generated for this target.
include CMakeFiles/mainClient.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/mainClient.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/mainClient.dir/flags.make

CMakeFiles/mainClient.dir/client/mainClient.c.o: CMakeFiles/mainClient.dir/flags.make
CMakeFiles/mainClient.dir/client/mainClient.c.o: client/mainClient.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/mainClient.dir/client/mainClient.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainClient.dir/client/mainClient.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/client/mainClient.c

CMakeFiles/mainClient.dir/client/mainClient.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainClient.dir/client/mainClient.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/client/mainClient.c > CMakeFiles/mainClient.dir/client/mainClient.c.i

CMakeFiles/mainClient.dir/client/mainClient.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainClient.dir/client/mainClient.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/client/mainClient.c -o CMakeFiles/mainClient.dir/client/mainClient.c.s

CMakeFiles/mainClient.dir/utils/aesUtils.c.o: CMakeFiles/mainClient.dir/flags.make
CMakeFiles/mainClient.dir/utils/aesUtils.c.o: utils/aesUtils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/mainClient.dir/utils/aesUtils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainClient.dir/utils/aesUtils.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/aesUtils.c

CMakeFiles/mainClient.dir/utils/aesUtils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainClient.dir/utils/aesUtils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/aesUtils.c > CMakeFiles/mainClient.dir/utils/aesUtils.c.i

CMakeFiles/mainClient.dir/utils/aesUtils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainClient.dir/utils/aesUtils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/aesUtils.c -o CMakeFiles/mainClient.dir/utils/aesUtils.c.s

CMakeFiles/mainClient.dir/cipherPOC.c.o: CMakeFiles/mainClient.dir/flags.make
CMakeFiles/mainClient.dir/cipherPOC.c.o: cipherPOC.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/mainClient.dir/cipherPOC.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainClient.dir/cipherPOC.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/cipherPOC.c

CMakeFiles/mainClient.dir/cipherPOC.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainClient.dir/cipherPOC.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/cipherPOC.c > CMakeFiles/mainClient.dir/cipherPOC.c.i

CMakeFiles/mainClient.dir/cipherPOC.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainClient.dir/cipherPOC.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/cipherPOC.c -o CMakeFiles/mainClient.dir/cipherPOC.c.s

CMakeFiles/mainClient.dir/signaturePOC.c.o: CMakeFiles/mainClient.dir/flags.make
CMakeFiles/mainClient.dir/signaturePOC.c.o: signaturePOC.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/mainClient.dir/signaturePOC.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainClient.dir/signaturePOC.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/signaturePOC.c

CMakeFiles/mainClient.dir/signaturePOC.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainClient.dir/signaturePOC.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/signaturePOC.c > CMakeFiles/mainClient.dir/signaturePOC.c.i

CMakeFiles/mainClient.dir/signaturePOC.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainClient.dir/signaturePOC.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/signaturePOC.c -o CMakeFiles/mainClient.dir/signaturePOC.c.s

CMakeFiles/mainClient.dir/utils/base64.c.o: CMakeFiles/mainClient.dir/flags.make
CMakeFiles/mainClient.dir/utils/base64.c.o: utils/base64.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/mainClient.dir/utils/base64.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainClient.dir/utils/base64.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/base64.c

CMakeFiles/mainClient.dir/utils/base64.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainClient.dir/utils/base64.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/base64.c > CMakeFiles/mainClient.dir/utils/base64.c.i

CMakeFiles/mainClient.dir/utils/base64.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainClient.dir/utils/base64.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/base64.c -o CMakeFiles/mainClient.dir/utils/base64.c.s

CMakeFiles/mainClient.dir/utils/socketUtils.c.o: CMakeFiles/mainClient.dir/flags.make
CMakeFiles/mainClient.dir/utils/socketUtils.c.o: utils/socketUtils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/mainClient.dir/utils/socketUtils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mainClient.dir/utils/socketUtils.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/socketUtils.c

CMakeFiles/mainClient.dir/utils/socketUtils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mainClient.dir/utils/socketUtils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/socketUtils.c > CMakeFiles/mainClient.dir/utils/socketUtils.c.i

CMakeFiles/mainClient.dir/utils/socketUtils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mainClient.dir/utils/socketUtils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/socketUtils.c -o CMakeFiles/mainClient.dir/utils/socketUtils.c.s

# Object files for target mainClient
mainClient_OBJECTS = \
"CMakeFiles/mainClient.dir/client/mainClient.c.o" \
"CMakeFiles/mainClient.dir/utils/aesUtils.c.o" \
"CMakeFiles/mainClient.dir/cipherPOC.c.o" \
"CMakeFiles/mainClient.dir/signaturePOC.c.o" \
"CMakeFiles/mainClient.dir/utils/base64.c.o" \
"CMakeFiles/mainClient.dir/utils/socketUtils.c.o"

# External object files for target mainClient
mainClient_EXTERNAL_OBJECTS =

mainClient: CMakeFiles/mainClient.dir/client/mainClient.c.o
mainClient: CMakeFiles/mainClient.dir/utils/aesUtils.c.o
mainClient: CMakeFiles/mainClient.dir/cipherPOC.c.o
mainClient: CMakeFiles/mainClient.dir/signaturePOC.c.o
mainClient: CMakeFiles/mainClient.dir/utils/base64.c.o
mainClient: CMakeFiles/mainClient.dir/utils/socketUtils.c.o
mainClient: CMakeFiles/mainClient.dir/build.make
mainClient: libs/relic-target/lib/librelic.so
mainClient: libs/unqlite/libunqlite.a
mainClient: libs/binn/libbinn.so.3.0
mainClient: CMakeFiles/mainClient.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking C executable mainClient"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/mainClient.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/mainClient.dir/build: mainClient

.PHONY : CMakeFiles/mainClient.dir/build

CMakeFiles/mainClient.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/mainClient.dir/cmake_clean.cmake
.PHONY : CMakeFiles/mainClient.dir/clean

CMakeFiles/mainClient.dir/depend:
	cd /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles/mainClient.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/mainClient.dir/depend

