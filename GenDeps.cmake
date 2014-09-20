add_custom_command(OUTPUT ${PROJECT_SOURCE_DIR}/include/openssl/obj_mac.h
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/crypto/objects"
  COMMAND perl objects.pl objects.txt obj_mac.num obj_mac.h && mv obj_mac.h ${PROJECT_SOURCE_DIR}/include/openssl/obj_mac.h
)

add_custom_target(obj_mac.h ALL
   DEPENDS ${PROJECT_SOURCE_DIR}/include/openssl/obj_mac.h
)

set_source_files_properties(${PROJECT_SOURCE_DIR}/include/openssl/obj_mac.h PROPERTIES GENERATED 1)
