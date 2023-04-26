#include "seal/seal.h"

#include <vector>

using namespace std;
using namespace seal;

inline string uint64_to_hex_string(uint64_t x) {
    return seal::util::uint_to_hex_string(&x, size_t(1));
}

inline void hex_string_to_uint64(string x, uint64_t *res) {
    seal::util::hex_string_to_uint(x.c_str(), x.size(), std::size_t(1), res);
}

uint64_t plain_modulus() {
    return 68720066561ull;
}

int main() {
    uint64_t polynomial_modulus = 8192;
    EncryptionParameters params(scheme_type::bfv);
    params.set_poly_modulus_degree(polynomial_modulus);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(polynomial_modulus));
    params.set_plain_modulus(plain_modulus());

    SEALContext ctx(params);

    KeyGenerator keygen(ctx);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;
    keygen.create_public_key(pk);

    Encryptor enc(ctx, pk);
    Evaluator eval(ctx);
    Decryptor dec(ctx, sk);

    Plaintext msg(uint64_to_hex_string(0x2));
    cout << "msg " << msg.to_string() << endl;
    Ciphertext c1;
    enc.encrypt(msg, c1);
    Ciphertext c2;
    enc.encrypt(msg, c2);

    vector<Plaintext> coeff = {Plaintext("3"), Plaintext("2"), Plaintext("1"), Plaintext("2")};

    Ciphertext res;
    eval.multiply_plain(c1, coeff[0], res);
    for (int i = 1; i < coeff.size() - 1; i++) {
        Plaintext tmp;

        dec.decrypt(res, tmp);
        std::cout << tmp.to_string() << std::endl;

        eval.add_plain_inplace(res, coeff[i]);

        dec.decrypt(res, tmp);
        std::cout << tmp.to_string() << std::endl;

        eval.multiply_inplace(res, c2);
    }

    Ciphertext r;
    eval.add_plain(res, coeff[3], r);
    Plaintext d;
    dec.decrypt(r, d);
    std::cout << "0x" << d.to_string() << std::endl;
    // hex_string_to_uint64(d.to_string(), &resu);
    // std::cout << resu << std::endl;
}