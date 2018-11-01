#ifndef ETHSNARKS_EXPORT_HPP_
#define ETHSNARKS_EXPORT_HPP_

#include "ethsnarks.hpp"

namespace ethsnarks {

std::string HexStringFromBigint( LimbT _x);

std::string outputPointG1AffineAsHex( G1T _p );

std::string outputPointG2AffineAsHex( G2T _p );

std::string proof_to_json( ProofT &proof, const PrimaryInputT &input );

void proof2json_file(ProofT &proof, const PrimaryInputT &input, const std::string &path);

std::string vk2json( VerificationKeyT &vk );

void vk2json_file( VerificationKeyT &vk, const std::string &path );

}

#endif
