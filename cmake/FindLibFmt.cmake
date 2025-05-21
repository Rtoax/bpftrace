# - Try to find libfmt
# Once done this will define
#
#  LIBFMT_FOUND - system has libfmt
#  LIBFMT_INCLUDE_DIRS - the libfmt include directory
#  LIBFMT_LIBRARIES - Link these to use libfmt

if (LIBFMT_LIBRARIES AND LIBFMT_INCLUDE_DIRS)
  set (LibFmt_FIND_QUIETLY TRUE)
endif (LIBFMT_LIBRARIES AND LIBFMT_INCLUDE_DIRS)

find_path (LIBFMT_INCLUDE_DIRS
  NAMES
    fmt/format.h
  PATHS
    ENV CPATH)

find_library (LIBFMT_LIBRARIES
  NAMES
    fmt
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBFMT_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibFmt "Please install the libfmt development package"
  LIBFMT_LIBRARIES
  LIBFMT_INCLUDE_DIRS)

mark_as_advanced(LIBFMT_INCLUDE_DIRS LIBFMT_LIBRARIES)
