# Source directories
SRC_DIRS = 

# Output directory
OUT_DIR = bin

#Executable name
EXECUTABLE = $(OUT_DIR)/test.exe

# Compiler flags
INCLUDE_PATH = -I.
DEFINE_SYMBOL = -D_UNICODE -DUNICODE -DWIN32 -D_WINDOWS
CFLAGS = -c -O1 -Wall -Wextra -pedantic-errors -std=c++17 -ggdb $(INCLUDE_PATH) $(DEFINE_SYMBOL) -mwindows

# Linker Flags
LDFLAGS = -lwinhttp

CC = g++
MD = mkdir
RM = rmdir /S /Q
CP = copy /Y 

# Compute buil dirs (before modify SRC_DIRS)
BUILD_DIRS_0 = $(addprefix $(OUT_DIR)\,$(SRC_DIRS))
BUILD_DIRS = $(subst /,\,$(BUILD_DIRS_0))

# Sources
SRC_DIRS += .
SOURCES = $(foreach sdir,$(SRC_DIRS),$(wildcard $(sdir)/*.cpp))

SRCOBJECTS = $(SOURCES:.cpp=.o)
OBJECTS = $(patsubst %,$(OUT_DIR)/%,$(SRCOBJECTS))

# Make
all: directories $(SOURCES) $(EXECUTABLE)

# Directories
directories: $(OUT_DIR) $(BUILD_DIRS)

$(OUT_DIR):
	$(MD) $(OUT_DIR)

$(BUILD_DIRS):
	$(MD) $@

# Link
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile
bin/%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@

# Clean
clean:
	$(RM) $(OUT_DIR)\
