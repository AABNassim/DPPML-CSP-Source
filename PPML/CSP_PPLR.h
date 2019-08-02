//
// Created by Nassim AAB on 2019-07-27.
//

#ifndef DPPML_CSP_PPLR_H
#define DPPML_CSP_PPLR_H

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "HEAAN.h"

#include <vector>
#include <Ciphertext.h>
#include <cstdlib>
#include <chrono>
#include "../ML/DatasetReader.h"
#include "../PPML/MLSP.h"
#include <cmath>
#include "../ML/LogisticRegression.h"
#include <string.h>

#include <iomanip>
#include <ctime>
#include <sstream>

#include "../CRYPTO/DTPKC.h"
#include "../CRYPTO/EvalAdd.h"


using namespace std;

class CSP_PPLR {
public:

    // Network attributes
    int server_fd, new_socket;
    int port = 8080;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello = "Hello from server";

    // Network functions
    CSP_PPLR();
    bool read_file(int sock, char* path);
    void test_read_file();
    void test_key_exchange();
    bool send_file(int sock, char* path);
    bool read_long(int sock, long *value);
    bool read_data(int sock, void *buf, int buflen);
    bool send_long(int sock, long value);
    bool send_data(int sock, void *buf, int buflen);

    // Logistic Regression..

    long logp = 30; ///< Scaling Factor (larger logp will give you more accurate value)
    long logn = 10; ///< number of slot is 1024 (this value should be < logN in "src/Params.h")
    long logq = 300; ///< Ciphertext modulus (this value should be <= logQ in "scr/Params.h")
    long n = 1 << logn;
    long numThread = 5;
    double alpha = 1;
    int epochs = 30;
    int nb_slots = n;
    int nb_rows = 64;
    int nb_cols = 16;
    int log_nb_cols = 4;
    int log_nb_rows = 6;
    int d = 10;
    int class_number = 2;
    int sigmoid_degree = 3;
    int nb_training_ciphers = 8;
    int m = nb_rows * nb_training_ciphers;

    Ring ring;
    SecretKey secretKey;
    Scheme scheme;


    gmp_randstate_t randstate;
    mpz_class dtpkc_pkey, dtpkc_skey;
    int precision = 30;
    int nb_bits = 1024, error = 100;
    DTPKC dtpkc;

    long dtpkc_scale_factor = pow(10, 6);


    string dataset_name = "Edin";
    string datasets_path = "../DATA/Datasets/";
    vector<Ciphertext> cipher_training_set;
    Ciphertext cipher_model;
    //vector<double> sigmoid_coeffs_deg3 = {0.5, 0.15012, -0.0015930078125};
    vector<double> sigmoid_coeffs_deg3 = {0.5, -1.20096, 0.81562};
    vector<double> sigmoid_coeffs_deg5 = {0.5, 1.53048, -2.3533056, 1.3511295};
    vector<double> sigmoid_coeffs_deg7 = {0.5, 1.73496, -4.19407, 5.43402, -2.50739};

    Ciphertext cipher_gadget_matrix;

    complex<double> *encoded_sigmoid_coeffs;
    Ciphertext cipher_sigmoid_coeffs;

    Ciphertext pp_sigmoid_deg3(Ciphertext cipher_x);
    void test_pp_sigmoid(vector<double> x);
    double approx_sigmoid_deg3(double x);
    void pp_fit();
    void encrypt_dataset();
    vector<Record*> decrypt_dataset();
    Ciphertext pp_dot_product(Ciphertext cx, Ciphertext cy);
    void test_pp_dot_product(vector<double> x, vector<double> y);
    Ciphertext sum_slots(Ciphertext c, int start_slot, int end_slot);
    Ciphertext sum_slots_reversed(Ciphertext c, int start_slot, int end_slot);
    void test_sum_slots();

    void test_cryptosystem_switching_local();
    void test_cryptosystem_switching_single();

    Ciphertext cryptosystem_switching_single_local(DTPKC::Cipher dtpkc_value);
    void cryptosystem_switching_single();

    void cryptosystem_switching_batch_naive();
    void cryptosystem_switching_batch_optimized();
    void test_cryptosystem_switching_batch_optimized();
    void test_cryptosystem_switching_batch_naive();

    Ciphertext refresh_cipher_local_unsecure(Ciphertext c);

    Ciphertext refresh_cipher_local(Ciphertext c);

    void refresh_cipher_unsecure();
    void test_refresh_cipher_unsecure();

    void refresh_cipher();
    void test_refresh_cipher();

    void refresh_cipher_unsecure_old();
    void refresh_cipher_old();

    DTPKC::Cipher receive_dtpkc_cipher();

    void pp_fit_local();

    void debug();


    };


#endif //DPPML_CSP_PPLR_H
