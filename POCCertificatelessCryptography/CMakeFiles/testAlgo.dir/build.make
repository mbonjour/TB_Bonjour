# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


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
CMAKE_COMMAND = /home/mbonjour/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/201.7846.88/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/mbonjour/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/201.7846.88/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography

# Include any dependencies generated for this target.
include CMakeFiles/testAlgo.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/testAlgo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/testAlgo.dir/flags.make

CMakeFiles/testAlgo.dir/test/fullTest.c.o: CMakeFiles/testAlgo.dir/flags.make
CMakeFiles/testAlgo.dir/test/fullTest.c.o: test/fullTest.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/testAlgo.dir/test/fullTest.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/testAlgo.dir/test/fullTest.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/test/fullTest.c

CMakeFiles/testAlgo.dir/test/fullTest.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/testAlgo.dir/test/fullTest.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/test/fullTest.c > CMakeFiles/testAlgo.dir/test/fullTest.c.i

CMakeFiles/testAlgo.dir/test/fullTest.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/testAlgo.dir/test/fullTest.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/test/fullTest.c -o CMakeFiles/testAlgo.dir/test/fullTest.c.s

CMakeFiles/testAlgo.dir/utils/aesUtils.c.o: CMakeFiles/testAlgo.dir/flags.make
CMakeFiles/testAlgo.dir/utils/aesUtils.c.o: utils/aesUtils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/testAlgo.dir/utils/aesUtils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/testAlgo.dir/utils/aesUtils.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/aesUtils.c

CMakeFiles/testAlgo.dir/utils/aesUtils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/testAlgo.dir/utils/aesUtils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/aesUtils.c > CMakeFiles/testAlgo.dir/utils/aesUtils.c.i

CMakeFiles/testAlgo.dir/utils/aesUtils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/testAlgo.dir/utils/aesUtils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/aesUtils.c -o CMakeFiles/testAlgo.dir/utils/aesUtils.c.s

CMakeFiles/testAlgo.dir/cipherPOC.c.o: CMakeFiles/testAlgo.dir/flags.make
CMakeFiles/testAlgo.dir/cipherPOC.c.o: cipherPOC.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/testAlgo.dir/cipherPOC.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/testAlgo.dir/cipherPOC.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/cipherPOC.c

CMakeFiles/testAlgo.dir/cipherPOC.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/testAlgo.dir/cipherPOC.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/cipherPOC.c > CMakeFiles/testAlgo.dir/cipherPOC.c.i

CMakeFiles/testAlgo.dir/cipherPOC.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/testAlgo.dir/cipherPOC.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/cipherPOC.c -o CMakeFiles/testAlgo.dir/cipherPOC.c.s

CMakeFiles/testAlgo.dir/signaturePOC.c.o: CMakeFiles/testAlgo.dir/flags.make
CMakeFiles/testAlgo.dir/signaturePOC.c.o: signaturePOC.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/testAlgo.dir/signaturePOC.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/testAlgo.dir/signaturePOC.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/signaturePOC.c

CMakeFiles/testAlgo.dir/signaturePOC.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/testAlgo.dir/signaturePOC.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/signaturePOC.c > CMakeFiles/testAlgo.dir/signaturePOC.c.i

CMakeFiles/testAlgo.dir/signaturePOC.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/testAlgo.dir/signaturePOC.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/signaturePOC.c -o CMakeFiles/testAlgo.dir/signaturePOC.c.s

CMakeFiles/testAlgo.dir/utils/base64.c.o: CMakeFiles/testAlgo.dir/flags.make
CMakeFiles/testAlgo.dir/utils/base64.c.o: utils/base64.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/testAlgo.dir/utils/base64.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/testAlgo.dir/utils/base64.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/base64.c

CMakeFiles/testAlgo.dir/utils/base64.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/testAlgo.dir/utils/base64.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/base64.c > CMakeFiles/testAlgo.dir/utils/base64.c.i

CMakeFiles/testAlgo.dir/utils/base64.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/testAlgo.dir/utils/base64.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/base64.c -o CMakeFiles/testAlgo.dir/utils/base64.c.s

CMakeFiles/testAlgo.dir/utils/socketUtils.c.o: CMakeFiles/testAlgo.dir/flags.make
CMakeFiles/testAlgo.dir/utils/socketUtils.c.o: utils/socketUtils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/testAlgo.dir/utils/socketUtils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/testAlgo.dir/utils/socketUtils.c.o   -c /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/socketUtils.c

CMakeFiles/testAlgo.dir/utils/socketUtils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/testAlgo.dir/utils/socketUtils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/socketUtils.c > CMakeFiles/testAlgo.dir/utils/socketUtils.c.i

CMakeFiles/testAlgo.dir/utils/socketUtils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/testAlgo.dir/utils/socketUtils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/utils/socketUtils.c -o CMakeFiles/testAlgo.dir/utils/socketUtils.c.s

# Object files for target testAlgo
testAlgo_OBJECTS = \
"CMakeFiles/testAlgo.dir/test/fullTest.c.o" \
"CMakeFiles/testAlgo.dir/utils/aesUtils.c.o" \
"CMakeFiles/testAlgo.dir/cipherPOC.c.o" \
"CMakeFiles/testAlgo.dir/signaturePOC.c.o" \
"CMakeFiles/testAlgo.dir/utils/base64.c.o" \
"CMakeFiles/testAlgo.dir/utils/socketUtils.c.o"

# External object files for target testAlgo
testAlgo_EXTERNAL_OBJECTS =

testAlgo: CMakeFiles/testAlgo.dir/test/fullTest.c.o
testAlgo: CMakeFiles/testAlgo.dir/utils/aesUtils.c.o
testAlgo: CMakeFiles/testAlgo.dir/cipherPOC.c.o
testAlgo: CMakeFiles/testAlgo.dir/signaturePOC.c.o
testAlgo: CMakeFiles/testAlgo.dir/utils/base64.c.o
testAlgo: CMakeFiles/testAlgo.dir/utils/socketUtils.c.o
testAlgo: CMakeFiles/testAlgo.dir/build.make
testAlgo: libs/relic-target/lib/librelic.so
testAlgo: libs/unqlite/libunqlite.a
testAlgo: CMakeFiles/testAlgo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking C executable testAlgo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/testAlgo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/testAlgo.dir/build: testAlgo

.PHONY : CMakeFiles/testAlgo.dir/build

CMakeFiles/testAlgo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/testAlgo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/testAlgo.dir/clean

CMakeFiles/testAlgo.dir/depend:
	cd /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography /home/mbonjour/HEIG-VD/annee3/semestre_2/TB/TB_Bonjour/POCCertificatelessCryptography/CMakeFiles/testAlgo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/testAlgo.dir/depend

