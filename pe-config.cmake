# Library configuration file used by dependent projects
# via find_package() built-in directive in "config" mode.

if(NOT DEFINED PE_FOUND)

  # Locate library headers.
  FIND_PATH(PE_INCLUDE_DIRS 
    NAMES pe.h
    PATHS ${PE_DIR}
  )

  # Common name for exported library targets.
  SET(PE_LIBRARIES
    pe
    CACHE INTERNAL "pe library" FORCE
  )

  # Usual "required" et. al. directive logic.
  INCLUDE(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(
    pe DEFAULT_MSG
    PE_INCLUDE_DIRS
    PE_LIBRARIES
  )

  # Add targets to dependent project.
  add_subdirectory(
    ${PE_DIR}
    ${CMAKE_BINARY_DIR}/pe
  )
endif()
