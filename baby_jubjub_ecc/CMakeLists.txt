include_directories(.)

add_executable(
        generator

        generator.cpp
)

add_executable(
        prover

        prover.cpp
)

add_library(
        baby_jubjub_ecc
        STATIC

        pedersen_commitment.hpp

        baby_jubjub.hpp

        eddsa.hpp
)

target_link_libraries(
        baby_jubjub_ecc
        snark
)


target_link_libraries(
        generator
        snark
        baby_jubjub_ecc
)

target_link_libraries(
        prover
        snark
        baby_jubjub_ecc
)

set_property(TARGET baby_jubjub_ecc PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(
        baby_jubjub_ecc
        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libff
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

target_include_directories(
        generator
        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libff
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
