//
// Created by Nassim AAB on 2019-07-27.
//

#include "CSP_PPLR.h"


CSP_PPLR::CSP_PPLR(void) : secretKey(ring), scheme(secretKey, ring, false) {

    // Generate the cryptosystem keys
    SetNumThreads(2);

    //SecretKey secretKey(ring);
    //Scheme scheme(secretKey, ring);
    //scheme.addLeftRotKeys(secretKey); ///< When you need left rotation for the vectorized message
    //scheme.addRightRotKeys(secretKey); ///< When you need right rotation for the vectorized message

    //scheme.read_keys();

    complex<double> *mvec1 = new complex<double>[n];

    for (int i = 0; i < n; ++i) {
        complex<double> c;
        c.real(1);
        c.imag(0);
        mvec1[i] = c;
    }

    Ciphertext cipher1;
    scheme.encrypt(cipher1, mvec1, n, logp, logq);

    complex<double> *dvec = scheme.decrypt(secretKey, cipher1);

    cout << "FHE decrypt result:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << dvec[i] << ' ';
    }
    cout << " " << endl;

    // Deserialize DTPKC
    ///dtpkc.deserializeDtpkc("./");
    //dtpkc_pkey = dtpkc.pkw;

    // Test the cryptosystem switching
    //test_cryptosystem_switching();


    cout << "Proceed to connection" << endl;
    // Connect to the MLSP
    int valread;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Forcefully attaching socket to the port 8080
    if (::bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind error");
    }

    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Exchange the keys

    // Next..
    cout << "Tout est bon" << endl;
    //

    encoded_sigmoid_coeffs = new complex<double>[n]; // TODO : Useless ?
    for (int i = 0; i < sigmoid_degree; i++) {
        complex<double> c;
        c.imag(0);
        c.real(sigmoid_coeffs_deg3[i]);
        encoded_sigmoid_coeffs[i] = c;
    }
    scheme.encrypt(cipher_sigmoid_coeffs, encoded_sigmoid_coeffs, n, logp, logq);

    // Model initialization
    complex<double> *encoded_model = new complex<double>[n];
    for (int i = 0; i < n; i++) {
        complex<double> c;
        c.imag(0);
        c.real(0);
        encoded_model[i] = c;
    }
    scheme.encrypt(cipher_model, encoded_model, n, logp, logq);

    // Toy Matrix creation
    complex<double> *encoded_gadget_matrix = new complex<double>[n];
    for (int i = 0; i < n; i++) {
        complex<double> c;
        c.imag(0);
        c.real(0);
        encoded_gadget_matrix[i] = c;
    }
    for (int i = 0; i < nb_rows; i++) {
        complex<double> c;
        c.imag(0);
        c.real(1);
        encoded_gadget_matrix[i * nb_cols] = c;
    }
    scheme.encrypt(cipher_gadget_matrix, encoded_gadget_matrix, n, logp, logq);    //TODO : what's happening ?*/

}



bool CSP_PPLR::send_data(int sock, void *buf, int buflen)
{
    unsigned char *pbuf = (unsigned char *) buf;

    while (buflen > 0)
    {
        int num = send(sock, pbuf, buflen, 0);

        pbuf += num;
        buflen -= num;
    }

    return true;
}


bool CSP_PPLR::send_long(int sock, long value)
{
    value = htonl(value);
    return send_data(sock, &value, sizeof(value));
}



bool CSP_PPLR::send_file(int sock, char* path)
{
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    rewind(f);
    if (filesize == EOF)
        return false;
    if (!send_long(sock, filesize))
        return false;
    if (filesize > 0)
    {
        char buffer[1024];
        do
        {
            size_t num = (filesize < sizeof(buffer)) ?  filesize : sizeof(buffer);
            num = fread(buffer, 1, num, f);
            if (num < 1)
                return false;
            if (!send_data(sock, buffer, num))
                return false;
            filesize -= num;
        }
        while (filesize > 0);
    }
    return true;
}



bool CSP_PPLR::read_data(int sock, void *buf, int buflen)
{
    unsigned char *pbuf = (unsigned char *) buf;

    while (buflen > 0)
    {
        int num = recv(sock, pbuf, buflen, 0);
        if (num == 0)
            return false;

        pbuf += num;
        buflen -= num;
    }

    return true;
}

bool CSP_PPLR::read_long(int sock, long *value)
{
    if (!read_data(sock, value, sizeof(value)))
        return false;
    *value = ntohl(*value);
    return true;
}


bool CSP_PPLR::read_file(int sock, char* path)
{
    FILE *f = fopen(path, "wb");
    long filesize;
    if (!read_long(sock, &filesize)) {
        return false;
    }
    if (filesize > 0)
    {
        //cout << "Getting a file of size : " << filesize << endl;
        char buffer[1024];
        do
        {
            int num = (filesize < sizeof(buffer)) ?  filesize : sizeof(buffer);
            if (!read_data(sock, buffer, num))
                return false;
            int offset = 0;
            do
            {
                size_t written = fwrite(&buffer[offset], 1, num - offset, f);
                if (written < 1)
                    return false;
                offset += written;
            }
            while (offset < num);
            filesize -= num;
        }
        while (filesize > 0);
    }
    return true;
}

void CSP_PPLR::test_read_file() {
    read_file(new_socket, "test_write_cipher.txt");
}

void CSP_PPLR::test_key_exchange() {
    return;
    long val;
    if (read_long(new_socket, &val)) {
        cout << "Got the number : " << val << endl;
    }

    // Send the cryptographic keys
    if (send_file(new_socket, "serkey/ENCRYPTION_KEY.txt")) {
        cout << "Okay, now send the keys" << endl;

        // Now, get the test cipher
        read_file(new_socket, "cipher_test.txt");

        cout << "Already read the test cipher" << endl;

        Ciphertext* test_cipher = SerializationUtils::readCiphertext("cipher_test.txt");
        complex<double> *decrypted_cipher1 = scheme.decrypt(secretKey, *test_cipher);

        cout << "Decryption test cipher:" << endl;
        for (int i = 0; i < d; ++i) {
            cout << decrypted_cipher1[i] << ' ';
        }
        cout << " " << endl;

        // Send the multiplication key

        if (send_file(new_socket, "serkey/MULTIPLICATION_KEY.txt")) {
            // Now, we test the multiplication

            read_file(new_socket, "cipher_mult.txt");
            Ciphertext* mult_cipher = SerializationUtils::readCiphertext("cipher_mult.txt");
            complex<double> *decrypted_mult_cipher = scheme.decrypt(secretKey, *mult_cipher);

            cout << "Decryption mult cipher:" << endl;
            for (int i = 0; i < d; ++i) {
                cout << decrypted_mult_cipher[i] << ' ';
            }
            cout << " " << endl;
        }

        // Send the left rotation keys
        for (long i = 0; i < logN - 1; ++i) {
            //cout << "Rot " << i << endl;
            long idx = 1 << i;
            char* path = (char*) scheme.serLeftRotKeyMap.at(idx).c_str();
            if(send_file(new_socket, path)) {

            } else {
                cout << "ERROR : COULD NOT SEND THE ROTATION KEY" << endl;
            }
        }

        read_file(new_socket, "cipher_rot.txt");
        Ciphertext* left_rot_cipher = SerializationUtils::readCiphertext("cipher_rot.txt");
        complex<double> *decrypted_left_rot_cipher = scheme.decrypt(secretKey, *left_rot_cipher);

        cout << "Decryption rot cipher:" << endl;
        for (int i = 0; i < d; ++i) {
            cout << decrypted_left_rot_cipher[i] << ' ';
        }
        cout << " " << endl;

        // Send right rotation keys
        for (long i = 0; i < logN - 1; ++i) {
            //cout << "Rot " << i << endl;
            long idx = Nh - (1 << i);
            char* path = (char*) scheme.serLeftRotKeyMap.at(idx).c_str();
            if(send_file(new_socket, path)) {

            } else {
                cout << "ERROR : COULD NOT SEND THE ROTATION KEY" << endl;
            }
        }
        read_file(new_socket, "cipher_right_rot.txt");

        Ciphertext* right_rot_cipher = SerializationUtils::readCiphertext("cipher_right_rot.txt");
        complex<double> *decrypted_right_rot_cipher = scheme.decrypt(secretKey, *right_rot_cipher);

        cout << "Decryption right rot cipher:" << endl;
        for (int i = 0; i < d; ++i) {
            cout << decrypted_right_rot_cipher[i] << ' ';
        }
        cout << " " << endl;


    } else {
        cout << "ERROR : COULD NOT SEND THE ENCRYPTION KEY" << endl;
    }

}


DTPKC::Cipher CSP_PPLR::receive_dtpkc_cipher() {
    char *buf = new char[2048];
    memset(buf, 0, 2048);
    read_data(new_socket, buf, 2048);

    DTPKC::Cipher c;

    char *v = strtok(buf, ",");

    c.T1.set_str(v, 10);
    v = strtok(NULL, ",");
    c.T2.set_str(v, 10);
    c.Pub = dtpkc.pkw;

    mpz_class mpz_value = dtpkc.Sdec(c);

    long decrypted_value = mpz_value.get_si();

    return c;


    cout << buf << endl;
}


// ------------------------------------ LOGISTIC REGRESSION -------------------------------------------

void CSP_PPLR::encrypt_dataset() {
    DatasetReader *datasetReader = new DatasetReader(datasets_path + dataset_name + "/", class_number, d);
    complex<double> *vectorized_batch = new complex<double>[nb_slots];
    vector<Record*> training_data = datasetReader->read_all_train_records();

    for (int i = 0; i < m; i++) {
        training_data[i]->print();
    }

    for (int i = 0; i < n; i++) {
        complex<double> c;
        c.imag(0);
        c.real(0);
        vectorized_batch[i] = c;
    }

    for (int i = 0; i < nb_training_ciphers; i++) {
        Ciphertext cipher_training_batch;
        vectorized_batch = new complex<double>[nb_slots];
        for (int j = 0; j < nb_rows; j++) {
            Record *rcd = training_data[i * nb_rows + j];
            for (int k = 0; k < d; k++) {
                complex<double> c;
                int label;
                if (rcd->label == 0) {
                    label = -1;
                } else {
                    label = 1;
                }
                c.imag(0);
                c.real(rcd->values[k] * label);
                vectorized_batch[j * nb_cols + k] = c;
            }
        }
        scheme.encrypt(cipher_training_batch, vectorized_batch, n, logp, logq);
        cipher_training_set.push_back(cipher_training_batch);
    }
}

vector<Record*> CSP_PPLR::decrypt_dataset() {
    vector<Record*> records(m);
    for (int i = 0; i < nb_training_ciphers; i++) {
        complex<double> *decrypted_training_batch = scheme.decrypt(secretKey, cipher_training_set[i]);
        for (int j = 0; j < nb_rows; j++) {
            vector<int> values(d);
            for (int k = 0; k < d; k++) {
                complex<double> val = decrypted_training_batch[j * nb_cols + k];
                values[k] = (int) round(val.real());
            }

            Record* rcd = new Record(i * nb_rows + j, values, 0);
            records[i * nb_rows + j] = rcd;
            rcd->print();
        }
    }
    return records;
}

Ciphertext CSP_PPLR::refresh_cipher_local_unsecure(Ciphertext c) {
    complex<double> * plaintext = scheme.decrypt(secretKey, c);
    Ciphertext refreshed_c;
    scheme.encrypt(refreshed_c, plaintext, n, logp, logq);
    return refreshed_c;
}

void CSP_PPLR::refresh_cipher_unsecure_old() {
    read_file(new_socket, "cipher_to_refresh.txt");
    Ciphertext* cipher_to_refresh = SerializationUtils::readCiphertext("cipher_to_refresh.txt");

    complex<double> * plaintext = scheme.decrypt(secretKey, *cipher_to_refresh);

    cout << "Plaintext value of the cipher to refresh:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << plaintext[i] << ' ';
    }
    cout << " " << endl;

    Ciphertext refreshed_c;
    scheme.encrypt(refreshed_c, plaintext, n, logp, logq);
    SerializationUtils::writeCiphertext(refreshed_c, "refreshed_cipher.txt");

    Ciphertext* check = SerializationUtils::readCiphertext("refreshed_cipher.txt");
    complex<double> * plain_check = scheme.decrypt(secretKey, *check);

    cout << "Small check:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << plain_check[i] << ' ';
    }
    cout << " " << endl;

    if (send_file(new_socket, "refreshed_cipher.txt")) {
        cout << "Sent the refreshed cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }

    /*if (remove("cipher_to_refresh.txt") != 0)
        perror("Error deleting file");
    else
        puts("File successfully deleted");

    if (remove("refreshed_cipher.txt") != 0)
        perror("Error deleting file");
    else
        puts("File successfully deleted");*/
}


void CSP_PPLR::refresh_cipher_unsecure() {
    read_file(new_socket, "cipher_to_refresh.txt");
    Ciphertext* cipher_to_refresh = SerializationUtils::readCiphertext("cipher_to_refresh.txt");

    /*complex<double> * plaintext = scheme.decrypt(secretKey, *cipher_to_refresh);

    cout << "Plaintext value of the cipher to refresh:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << plaintext[i] << ' ';
    }
    cout << " " << endl;*/

    /*Ciphertext refreshed_c;
    scheme.encrypt(refreshed_c, plaintext, n, logp, logq);*/
    SerializationUtils::writeCiphertext(*cipher_to_refresh, "refreshed_cipher.txt");

    Ciphertext* check = SerializationUtils::readCiphertext("refreshed_cipher.txt");
    complex<double> * plain_check = scheme.decrypt(secretKey, *check);

    cout << "Small check:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plain_check[i] << ' ';
    }
    cout << " " << endl;

    if (send_file(new_socket, "refreshed_cipher.txt")) {
        cout << "Sent the refreshed cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }

    /*if (remove("cipher_to_refresh.txt") != 0)
        perror("Error deleting file");
    else
        puts("File successfully deleted");

    if (remove("refreshed_cipher.txt") != 0)
        perror("Error deleting file");
    else
        puts("File successfully deleted");*/
}



void CSP_PPLR::refresh_cipher_old() {
    read_file(new_socket, "cipher_to_refresh.txt");
    Ciphertext* cipher_to_refresh = SerializationUtils::readCiphertext("cipher_to_refresh.txt");

    complex<double> * plaintext = scheme.decrypt(secretKey, *cipher_to_refresh);

    cout << "Plaintext value of the cipher to refresh:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext[i] << ' ';
    }
    cout << " " << endl;

    Ciphertext refreshed_c;
    scheme.encrypt(refreshed_c, plaintext, n, logp, logq);
    SerializationUtils::writeCiphertext(refreshed_c, "refreshed_cipher.txt");


    if (send_file(new_socket, "refreshed_cipher.txt")) {
        cout << "Sent the refreshed cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }
}


void CSP_PPLR::refresh_cipher() {
    read_file(new_socket, "cipher_to_refresh.txt");
    Ciphertext* cipher_to_refresh = SerializationUtils::readCiphertext("cipher_to_refresh.txt");

    complex<double> * plaintext = scheme.decrypt(secretKey, *cipher_to_refresh);

    cout << "Plaintext value of the cipher to refresh:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext[i] << ' ';
    }
    cout << " " << endl;

    /*Ciphertext refreshed_c;
    scheme.encrypt(refreshed_c, plaintext, n, logp, logq);*/
    SerializationUtils::writeCiphertext(*cipher_to_refresh, "refreshed_cipher.txt");

    if (send_file(new_socket, "refreshed_cipher.txt")) {
        cout << "Sent the refreshed cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }

    if (remove("cipher_to_refresh.txt") != 0)
        perror("Error deleting file");
    else
        puts("File successfully deleted");

    if (remove("refreshed_cipher.txt") != 0)
        perror("Error deleting file");
    else
        puts("File successfully deleted");
}



void CSP_PPLR::debug() {
    read_file(new_socket, "cipher1.txt");
    Ciphertext* cipher1 = SerializationUtils::readCiphertext("cipher1.txt");

    read_file(new_socket, "cipher2.txt");
    Ciphertext* cipher2 = SerializationUtils::readCiphertext("cipher2.txt");

    read_file(new_socket, "product.txt");
    Ciphertext* product = SerializationUtils::readCiphertext("product.txt");

    read_file(new_socket, "cipher_sig.txt");
    Ciphertext* cipher_sig = SerializationUtils::readCiphertext("cipher_sig.txt");

    Ciphertext cipher_product, cipher_sum, cipher_rot, cipher_cst_product;
    scheme.mult(cipher_product, *cipher1, *cipher2);
    scheme.reScaleByAndEqual(cipher_product, logp);

    scheme.add(cipher_sum, *cipher1, *cipher2);

    scheme.leftRotateFast(cipher_rot, *cipher1, 2);
    scheme.multByConst(cipher_cst_product, *cipher1, 3.0, logp);
    scheme.reScaleByAndEqual(cipher_cst_product, logp);

    complex<double> * plaintext_cipher1 = scheme.decrypt(secretKey, *cipher1);

    cout << "Plaintext value of cipher1:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext_cipher1[i] << ' ';
    }
    cout << " " << endl;

    complex<double> * plaintext_cipher2 = scheme.decrypt(secretKey, *cipher2);

    cout << "Plaintext value of cipher2:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext_cipher2[i] << ' ';
    }
    cout << " " << endl;

    complex<double> * prod = scheme.decrypt(secretKey, *product);

    cout << "Plaintext value of prod:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << prod[i] << ' ';
    }
    cout << " " << endl;

    complex<double> * sig = scheme.decrypt(secretKey, *cipher_sig);

    cout << "Plaintext value of sig:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << sig[i] << ' ';
    }
    cout << " " << endl;

    complex<double> * plaintext_sum = scheme.decrypt(secretKey, cipher_sum);

    cout << "Plaintext value of add:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext_sum[i] << ' ';
    }
    cout << " " << endl;

    complex<double> * plaintext_product = scheme.decrypt(secretKey, cipher_product);

    cout << "Plaintext value of mult:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext_product[i] << ' ';
    }
    cout << " " << endl;

    complex<double> * plaintext_cst_product = scheme.decrypt(secretKey, cipher_cst_product);

    cout << "Plaintext value of cst mult:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext_cst_product[i] << ' ';
    }
    cout << " " << endl;

    complex<double> * plaintext_rot = scheme.decrypt(secretKey, cipher_rot);

    cout << "Plaintext value of rot:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext_rot[i] << ' ';
    }
    cout << " " << endl;

    Ciphertext recrypted_cipher1, recrypted_cipher2, recrypted_prod;
    scheme.encrypt(recrypted_cipher1, plaintext_cipher1, n, logp, logq);
    scheme.encrypt(recrypted_cipher2, plaintext_cipher2, n, logp, logq);
    scheme.encrypt(recrypted_prod, prod, n, logp, logq);

    SerializationUtils::writeCiphertext(recrypted_cipher1, "recrypted_cipher1.txt");
    if (send_file(new_socket, "recrypted_cipher1.txt")) {
        cout << "Sent the cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }

    SerializationUtils::writeCiphertext(recrypted_cipher2, "recrypted_cipher2.txt");
    if (send_file(new_socket, "recrypted_cipher2.txt")) {
        cout << "Sent the cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }

    SerializationUtils::writeCiphertext(recrypted_prod, "recrypted_prod.txt");
    if (send_file(new_socket, "recrypted_prod.txt")) {
        cout << "Sent the cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }

    SerializationUtils::writeCiphertext(cipher_rot, "cipher_rot.txt");
    if (send_file(new_socket, "cipher_rot.txt")) {
        cout << "Sent the cipher" << endl;
    }
    else {
        cout << "ERROR, could not send the cipher" << endl;
    }

}

void CSP_PPLR::pp_fit() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    std::ostringstream oss;

    oss << std::put_time(&tm, "%Y-%m-%d %H-%M");
    auto weights_file_name = "CIPHER_WEIGHTS_" + oss.str();

    ofstream weights_log_file;

    weights_log_file.open(weights_file_name);

    for (int e = 0; e < epochs; e++) {
        refresh_cipher();
        /*read_file(new_socket, "cipher_weights.txt");
        Ciphertext *cipher_model = SerializationUtils::readCiphertext("cipher_weights.txt");

        complex<double> * weights = scheme.decrypt(secretKey, *cipher_model);

        for (int j = 0; j < 1; j++) {
            for (int k = 0; k < d; k++) {
                weights_log_file << weights[j * nb_cols + k].real() << ", ";
            }
            weights_log_file << "" << endl;
        }*/

    }
    weights_log_file.close();
}

void CSP_PPLR::pp_fit_local() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    std::ostringstream oss;

    oss << std::put_time(&tm, "%Y-%m-%d %H-%M");
    auto grads_file_name = "CIPHER_APPROX_GRADS_" + oss.str();
    auto weights_file_name = "CIPHER_WEIGHTS_" + oss.str();

    ofstream grads_log_file;
    ofstream weights_log_file;

    grads_log_file.open(grads_file_name);
    weights_log_file.open(weights_file_name);

    for (int e = 0; e < epochs; e++) {
        Ciphertext cipher_grad;
        complex<double> *encoded_grad = new complex<double>[n];
        for (int i = 0; i < n; i++) {
            complex<double> c;
            c.imag(0);
            c.real(0);
            encoded_grad[i] = c;
        }
        scheme.encrypt(cipher_grad, encoded_grad, n, logp, logq - 7 * logp);

        for (int i = 0; i < nb_training_ciphers; i++) {
            Ciphertext cipher_product;
            //Ciphertext cipher_dot_product;
            /*
            complex<double> *hhh = scheme.decrypt(secretKey, cipher_training_set);
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < nb_cols; j++) {
                    cout << hhh[i * nb_cols + j] << ", ";
                }
                cout << " " << endl;
            }
            cout << " " << endl;

            cout << "wa shit" << endl;*/
            scheme.mult(cipher_product, cipher_model, cipher_training_set[i]);   // TODO : modify
            scheme.reScaleByAndEqual(cipher_product, logp);

            /*
            complex<double> * deb = scheme.decrypt(secretKey, cipher_product);
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < nb_cols; j++) {
                    cout << deb[i * nb_cols + j] << ", ";
                }
                cout << " " << endl;
            }
            cout << " " << endl;

            */
            Ciphertext cipher_dot_product = sum_slots(cipher_product, 0, log_nb_cols);
            /*
            deb = scheme.decrypt(secretKey, cipher_dot_product);
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < nb_cols; j++) {
                    cout << deb[i * nb_cols + j] << ", ";
                }
                cout << " " << endl;
            }
            cout << " " << endl;*/


            scheme.multAndEqual(cipher_dot_product, cipher_gadget_matrix);

            scheme.reScaleByAndEqual(cipher_dot_product, logp);

            Ciphertext cipher_dot_product_duplicated = sum_slots_reversed(cipher_dot_product, 0, log_nb_cols);

            Ciphertext cipher_sig = pp_sigmoid_deg3(cipher_dot_product_duplicated);

            /*complex<double> * eups = scheme.decrypt(secretKey, cipher_sig);
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < nb_cols; j++) {
                    cout << eups[i * nb_cols + j] << ", ";
                }
                cout << " " << endl;
            }
            cout << " " << endl;*/


            scheme.multAndEqual(cipher_sig, cipher_training_set[i]); // TODO : modify
            scheme.reScaleByAndEqual(cipher_sig, logp);

            Ciphertext cipher_partial_grad = sum_slots(cipher_sig, log_nb_cols, log_nb_rows + log_nb_cols);
            cout << "CHOUF, EKUUUUTH " << cipher_partial_grad.logq << endl;
            scheme.addAndEqual(cipher_grad, cipher_partial_grad);
            /*complex<double> * lol = scheme.decrypt(secretKey, cipher_grad);
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < nb_cols; j++) {
                    cout << lol[i * nb_cols + j] << ", ";
                }
                cout << " " << endl;
            }
            cout << " " << endl;*/
        }

        scheme.multByConstAndEqual(cipher_grad, alpha / m, logp);
        scheme.reScaleByAndEqual(cipher_grad, logp);            //TODO: factor out

        cout << "Gradient n : " << e << endl;

        complex<double> * grad = scheme.decrypt(secretKey, cipher_grad);
        for (int j = 0; j < 1; j++) {
            for (int k = 0; k < d; k++) {
                grads_log_file << grad[j * nb_cols + k].real() << ", ";
            }
            grads_log_file << "" << endl;
        }
        cout << " " << endl;

        //scheme.encrypt(cipher_grad, grad, n, logp, logq);

        Ciphertext refreshed_grad = refresh_cipher_local(cipher_grad);
        scheme.addAndEqual(cipher_model, refreshed_grad);

        complex<double> * weights = scheme.decrypt(secretKey, cipher_model);

        for (int j = 0; j < 1; j++) {
            for (int k = 0; k < d; k++) {
                weights_log_file << weights[j * nb_cols + k].real() << ", ";
            }
            weights_log_file << "" << endl;
        }
        cout << " " << endl;
        //Ciphertext cipher_model_bis = refresh_cipher(cipher_model);
        //cipher_model = cipher_model_bis;
        //complex<double> * plaintext = scheme.decrypt(secretKey, cipher_model);
        //Ciphertext new_model;
        //cipher_model.free();
        //scheme.encrypt(new_model, plaintext, n, logp, logq);
    }
    grads_log_file.close();
    weights_log_file.close();
}

void CSP_PPLR::test_refresh_cipher() {
    refresh_cipher();
    read_file(new_socket, "check_cipher.txt");
    Ciphertext* check_cipher = SerializationUtils::readCiphertext("check_cipher.txt");

    complex<double> * plaintext = scheme.decrypt(secretKey, *check_cipher);

    cout << "Plaintext value of the check cipher:" << endl;
    for (int i = 0; i < d; ++i) {
        cout << plaintext[i] << ' ';
    }
    cout << " " << endl;
}

void CSP_PPLR::test_refresh_cipher_unsecure() {
    refresh_cipher_unsecure();
}



Ciphertext CSP_PPLR::refresh_cipher_local(Ciphertext c) {
    complex<double> * randomness = EvaluatorUtils::randomComplexArray(n);
    Ciphertext encrypted_randomness;
    Ciphertext encrypted_randomness_down;
    scheme.encrypt(encrypted_randomness, randomness, n, logp, logq);
    scheme.modDownBy(encrypted_randomness_down, encrypted_randomness, logq - c.logq);

    Ciphertext blinded_cipher;
    scheme.add(blinded_cipher, c, encrypted_randomness_down);

    complex<double> * blinded_plaintext = scheme.decrypt(secretKey, blinded_cipher);
    Ciphertext refreshed_c;
    scheme.encrypt(refreshed_c, blinded_plaintext, n, logp, logq);

    scheme.subAndEqual(refreshed_c, encrypted_randomness);
    return refreshed_c;
}

Ciphertext CSP_PPLR::sum_slots(Ciphertext c, int start_slot, int end_slot) {
    Ciphertext cipher_sum = c;
    for (int i = start_slot; i < end_slot; i++) {
        Ciphertext cipher_rot;
        //cout << "Rotating by : " << (int) pow(2, i) << endl;
        scheme.leftRotateFast(cipher_rot, cipher_sum, (int) pow(2, i));/// TODO: Consider iterative update
        //complex<double> * decrypted_sum = scheme.decrypt(secretKey, cipher_sum);
        scheme.addAndEqual(cipher_sum, cipher_rot);
    }
    return cipher_sum;
}

Ciphertext CSP_PPLR::sum_slots_reversed(Ciphertext c, int start_slot, int end_slot) {
    Ciphertext cipher_sum = c;
    for (int i = start_slot; i < end_slot; i++) {
        Ciphertext cipher_rot;
        //cout << "Rotating by : " << (int) pow(2, i) << endl;
        scheme.rightRotateFast(cipher_rot, cipher_sum, (int) pow(2, i));   // TODO: Consider iterative update
        //complex<double> * decrypted_sum = scheme.decrypt(secretKey, cipher_sum);
        scheme.addAndEqual(cipher_sum, cipher_rot);
    }
    return cipher_sum;
}

void CSP_PPLR::test_sum_slots() {
    complex<double> *encoded_x;
    vector<double> x{1, 1, 1, 1};
    Ciphertext cipher_x;
    long nb = x.size();
    encoded_x = new complex<double>[n];

    for (int i = 0; i < n; i++) {
        complex<double> c;
        c.imag(0);
        c.real(0);
        encoded_x[i] = c;
    }

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < nb_cols; j++) {
            complex<double> c;
            c.imag(0);
            c.real(i);
            encoded_x[i * nb_cols + j] = c;
        }
    }

    scheme.encrypt(cipher_x, encoded_x, n, logp, logq);

    Ciphertext cipher_sum = sum_slots(cipher_x, 0, log_nb_cols);
    scheme.multAndEqual(cipher_sum, cipher_gadget_matrix);
    scheme.reScaleByAndEqual(cipher_sum, logp);

    Ciphertext duplicated = sum_slots_reversed(cipher_sum, 0, log_nb_cols);

    complex<double> * decrypted_sum = scheme.decrypt(secretKey, duplicated);
    cout << " " << endl;

    cout << "Decrypted sums:" << endl;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < nb_cols; j++) {
            cout << decrypted_sum[i * nb_cols + j] << ", ";
        }
        cout << " " << endl;
    }
    cout << " " << endl;
}

Ciphertext CSP_PPLR::pp_sigmoid_deg3(Ciphertext cipher_x) {
    Ciphertext cipher_sig;
    Ciphertext cipher_x_cube;
    Ciphertext cipher_ax;
    Ciphertext cipher_ax_cube;

    complex<double> *eussou = scheme.decrypt(secretKey, cipher_x);

    cout << "Input: ";
    for (int i = 0; i < d; i++) {
        cout << eussou[i] << ", ";
    }
    cout << " " << endl;

    scheme.multByConstAndEqual(cipher_x, 0.125, logp);
    scheme.reScaleByAndEqual(cipher_x, logp);

    cout << "First Mul: ";
    scheme.mult(cipher_x_cube, cipher_x, cipher_x);
    scheme.reScaleByAndEqual(cipher_x_cube, logp);

    eussou = scheme.decrypt(secretKey, cipher_x_cube);

    for (int i = 0; i < d; i++) {
        cout << eussou[i] << ", ";
    }
    cout << " " << endl;

    cout << "Second Mul: ";
    scheme.mult(cipher_x_cube, cipher_x_cube, cipher_x);
    scheme.reScaleByAndEqual(cipher_x_cube, logp);

    eussou = scheme.decrypt(secretKey, cipher_x_cube);

    for (int i = 0; i < d; i++) {
        cout << eussou[i] << ", ";
    }
    cout << " " << endl;

    cout << "First Const Mul: ";
    scheme.multByConst(cipher_ax, cipher_x, sigmoid_coeffs_deg3[1], logp);
    scheme.reScaleByAndEqual(cipher_ax, logp);

    eussou = scheme.decrypt(secretKey, cipher_ax);
    //scheme.encrypt(cipher_ax, eussou, n, logp, logq);

    for (int i = 0; i < d; i++) {
        cout << eussou[i] << ", ";
    }
    cout << " " << endl;

    cout << "Second Const Mul: ";


    scheme.multByConst(cipher_sig, cipher_x_cube, sigmoid_coeffs_deg3[2], logp);
    scheme.reScaleByAndEqual(cipher_sig, logp);

    eussou = scheme.decrypt(secretKey, cipher_sig);

    for (int i = 0; i < d; i++) {
        cout << eussou[i] << ", ";
    }
    cout << " " << endl;

    cout << "Const add: ";

    scheme.addConstAndEqual(cipher_sig, sigmoid_coeffs_deg3[0], logp);

    eussou = scheme.decrypt(secretKey, cipher_sig);

    for (int i = 0; i < d; i++) {
        cout << eussou[i] << ", ";
    }
    cout << " " << endl;
    //scheme.encrypt(cipher_sig, eussou, n, logp, logq);

    cout << "ADD: ";

    Ciphertext cipher_result;
    scheme.modDownByAndEqual(cipher_ax, 2 * logp);

    scheme.add(cipher_result, cipher_sig, cipher_ax);

    cout << "Cipher Sig : " << cipher_sig.logq << " Cipher AX : " << cipher_ax.logq << endl;

    eussou = scheme.decrypt(secretKey, cipher_result);

    for (int i = 0; i < d; i++) {
        cout << eussou[i] << ", ";
    }
    cout << " " << endl;

    return cipher_result;
}

double CSP_PPLR::approx_sigmoid_deg3(double x) {
    return sigmoid_coeffs_deg3[0] + sigmoid_coeffs_deg3[1] * x + sigmoid_coeffs_deg3[2] * x * x * x;
}

void CSP_PPLR::test_pp_sigmoid(vector<double> x) {
    complex<double> *encoded_x;
    Ciphertext cipher_x;
    long nb = x.size();
    encoded_x = new complex<double>[n];

    for (int i = 0; i < n; i++) {
        complex<double> c;
        c.imag(0);
        c.real(0);
        encoded_x[i] = c;
    }

    for (int i = 0; i < nb; i++) {
        complex<double> c;
        c.imag(0);
        c.real(x[i]);
        encoded_x[i] = c;
    }

    scheme.encrypt(cipher_x, encoded_x, n, logp, logq);
    Ciphertext cipher_sig = pp_sigmoid_deg3(cipher_x);

    complex<double> *decrypted_encoded_sigmoids = scheme.decrypt(secretKey, cipher_sig);
    vector<double> decrypted_sig(nb);
    cout << "Values after decryption: " << endl;
    for (int i = 0; i < nb; i++) {
        decrypted_sig[i] = decrypted_encoded_sigmoids[i].real();
        cout << decrypted_sig[i] << ", ";
    }
    cout << " " << endl;

    cout << "Original Sigmoid Values" << endl;
    for (int i = 0; i < nb; i++) {
        double plain_sig = LogisticRegression::sigmoid(x[i]);
        cout << plain_sig << ", ";
    }
    cout << " " << endl;
    cout << "Plaintext Sigmoid Approx" << endl;
    for (int i = 0; i < nb; i++) {
        double approx_sig = approx_sigmoid_deg3(x[i]);
        cout << approx_sig << ", ";
    }
}

Ciphertext CSP_PPLR::pp_dot_product(Ciphertext cx, Ciphertext cy) {
    Ciphertext cipher_prod;
    scheme.mult(cipher_prod, cx, cy);
    scheme.reScaleByAndEqual(cipher_prod, logp);

    complex<double> *decrypted_product = scheme.decrypt(secretKey, cipher_prod);
    for (int i = 0; i < d; i++) {
        cout << decrypted_product[i] << ", ";
    }
    cout << " " << endl;

    Ciphertext dot_product = sum_slots(cipher_prod, 0, 10);

    complex<double> *decrypted_dot_product = scheme.decrypt(secretKey, dot_product);
    for (int i = 0; i < d; i++) {
        cout << decrypted_dot_product[i] << ", ";
    }
    cout << " " << endl;
    return dot_product;
}

void CSP_PPLR::test_pp_dot_product(vector<double> x, vector<double> y) {
    Ciphertext cx, cy;
    complex<double> *encoded_x, *encoded_y;

    long nb = x.size();
    encoded_x = new complex<double>[n];
    encoded_y = new complex<double>[n];
    for (int i = 0; i < nb; i++) {
        complex<double> c;
        c.imag(0);
        c.real(x[i]);
        encoded_x[i] = c;
    }

    for (int i = 0; i < nb; i++) {
        complex<double> c;
        c.imag(0);
        c.real(y[i]);
        encoded_y[i] = c;
    }

    scheme.encrypt(cx, encoded_x, n, logp, logq);
    scheme.encrypt(cy, encoded_y, n, logp, logq);

    Ciphertext cipher_dot_product = pp_dot_product(cx, cy);

    complex<double> *decrypted_dot_product = scheme.decrypt(secretKey, cipher_dot_product);
    for (int i = 0; i < d; i++) {
        cout << decrypted_dot_product[i] << ", ";
    }
    cout << " " << endl;
}

void CSP_PPLR::test_cryptosystem_switching_local() {
    DTPKC::Cipher dtpkc_value;

    double val = 1.11111;
    long val_scaled = (long) (val * dtpkc_scale_factor);
    mpz_class mpz_value;
    mpz_value.set_str(std::to_string(val_scaled), 10);
    dtpkc_value = dtpkc.enc(mpz_value, dtpkc_pkey);

    chrono::high_resolution_clock::time_point start_key_exchange = chrono::high_resolution_clock::now();

    Ciphertext fhe_value = cryptosystem_switching_single_local(dtpkc_value);

    complex<double> *encoded_value = scheme.decrypt(secretKey, fhe_value);


    cout << "Encoded values:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << encoded_value[i] << ' ';
    }
    cout << " " << endl;

    chrono::high_resolution_clock::time_point end_key_exchange = chrono::high_resolution_clock::now();
    auto duration_exchange = chrono::duration_cast<chrono::milliseconds>(end_key_exchange - start_key_exchange).count();
    cout << "Protocol V2 takes : " << duration_exchange / 1000 << "s." << endl;
}

Ciphertext CSP_PPLR::cryptosystem_switching_single_local(DTPKC::Cipher dtpkc_value) {
    DTPKC::Cipher dtpkc_randomness;
    DTPKC::Cipher dtpkc_value_blinded;

    long randomness = rand();

    mpz_class mpz_randomness;
    mpz_randomness.set_str(std::to_string(randomness), 10);
    mpz_class mpz_value;

    mpz_randomness.set_str(std::to_string(randomness), 10);
    dtpkc_randomness = dtpkc.enc(mpz_randomness, dtpkc_pkey);

    EvalAdd add(dtpkc_value, dtpkc_randomness);

    dtpkc_value_blinded = add.EvalAdd_U1();

    mpz_class mpz_value_blinded = dtpkc.Sdec(dtpkc_value_blinded);
    long decrypted_value_blinded = mpz_value_blinded.get_si();
    double rescaled_decrypted_value_blinded = (double) decrypted_value_blinded / dtpkc_scale_factor;
    double rescaled_randomness = (double) randomness / dtpkc_scale_factor;

    cout << "Blinded value after decryption:" << decrypted_value_blinded << endl;

    cout << "When you remove noise : " << decrypted_value_blinded - randomness << endl;

    cout << "Rescaled Blinded Decrypted Value : " << rescaled_decrypted_value_blinded << endl;
    cout << "Rescaled when you remove noise : " << rescaled_decrypted_value_blinded - rescaled_randomness << endl;


    Ciphertext fhe_value, fhe_rescaled_randomness, fhe_rescaled_value_blinded;
    complex<double> *encoded_randomness = new complex<double>[n];
    complex<double> *encoded_value_blinded = new complex<double>[n];

    {
        complex<double> c;
        c.real(rescaled_randomness);
        c.imag(0);
        encoded_randomness[0] = c;
    }
    {
        complex<double> c;
        c.real(rescaled_decrypted_value_blinded);
        c.imag(0);
        encoded_value_blinded[0] = c;
    }
    for (int i = 1; i < n; ++i) {
        complex<double> c;
        c.real(0);
        c.imag(0);
        encoded_randomness[i] = c;
        encoded_value_blinded[i] = c;
    }

    scheme.encrypt(fhe_rescaled_value_blinded, encoded_value_blinded, n, logp, logq);

    scheme.encrypt(fhe_rescaled_randomness, encoded_randomness, n, logp, logq);

    complex<double> *decrypted_blinded = scheme.decrypt(secretKey, fhe_rescaled_value_blinded);

    cout.precision(10);
    cout << "Decrypted Rescaled Encoded blinded values:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << decrypted_blinded[i] << ' ';
    }
    cout << " " << endl;
    scheme.sub(fhe_value, fhe_rescaled_value_blinded, fhe_rescaled_randomness);

    return fhe_value;
}

void CSP_PPLR::cryptosystem_switching_single() {

    DTPKC::Cipher dtpkc_value_blinded = receive_dtpkc_cipher();

    mpz_class mpz_value_blinded = dtpkc.Sdec(dtpkc_value_blinded);
    long decrypted_value_blinded = mpz_value_blinded.get_si();
    double rescaled_decrypted_value_blinded = (double) decrypted_value_blinded / dtpkc_scale_factor;

    cout << "Blinded value after decryption:" << decrypted_value_blinded << endl;
    cout << "Rescaled Blinded Decrypted Value : " << rescaled_decrypted_value_blinded << endl;


    Ciphertext fhe_rescaled_value_blinded;
    complex<double> *encoded_value_blinded = new complex<double>[n];

    {
        complex<double> c;
        c.real(rescaled_decrypted_value_blinded);
        c.imag(0);
        encoded_value_blinded[0] = c;
    }
    for (int i = 1; i < n; ++i) {
        complex<double> c;
        c.real(0);
        c.imag(0);
        encoded_value_blinded[i] = c;
    }

    scheme.encrypt(fhe_rescaled_value_blinded, encoded_value_blinded, n, logp, logq);
    SerializationUtils::writeCiphertext(fhe_rescaled_value_blinded, "blinded_cipher.txt");

    if (send_file(new_socket, "blinded_cipher.txt")) {
        cout << "Sent the blinded Cipher" << endl;
    } else {
        cout << "ERROR while sending the blinded cipher" << endl;
    }
}

void CSP_PPLR::test_cryptosystem_switching_single() {

    cryptosystem_switching_single();
    read_file(new_socket, "fhe_cipher.txt");
    Ciphertext* fhe_cipher = SerializationUtils::readCiphertext("fhe_cipher.txt");

    complex<double> *encoded_value = scheme.decrypt(secretKey, *fhe_cipher);

    cout << "Encoded values:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << encoded_value[i] << ' ';
    }
    cout << " " << endl;
}

void CSP_PPLR::cryptosystem_switching_batch_naive() {
    int nb_vals = 4;
    Ciphertext fhe_rescaled_value_blinded;
    complex<double> *encoded_value_blinded = new complex<double>[n];

    for (int i = 0; i < n; ++i) {
        complex<double> c;
        c.real(0);
        c.imag(0);
        encoded_value_blinded[i] = c;
    }

    for (int i = 0; i < nb_vals; i++) {
        DTPKC::Cipher dtpkc_value_blinded = receive_dtpkc_cipher();

        mpz_class mpz_value_blinded = dtpkc.Sdec(dtpkc_value_blinded);
        long decrypted_value_blinded = mpz_value_blinded.get_si();
        double rescaled_decrypted_value_blinded = (double) decrypted_value_blinded / dtpkc_scale_factor;

        {
            complex<double> c;
            c.real(rescaled_decrypted_value_blinded);
            c.imag(0);
            encoded_value_blinded[i] = c;
        }
    }

    scheme.encrypt(fhe_rescaled_value_blinded, encoded_value_blinded, n, logp, logq);

    SerializationUtils::writeCiphertext(fhe_rescaled_value_blinded, "blinded_cipher.txt");

    if (send_file(new_socket, "blinded_cipher.txt")) {
        cout << "Sent the blinded Cipher" << endl;
    } else {
        cout << "ERROR while sending the blinded cipher" << endl;
    }
}

void CSP_PPLR::cryptosystem_switching_batch_optimized() {
    long nb_vals = 1;
    int dtpkc_nb_slots = dtpkc.nb_slots;
    Ciphertext fhe_rescaled_value_blinded;
    complex<double> *encoded_value_blinded = new complex<double>[n];

    for (int i = 0; i < n; ++i) {
        complex<double> c;
        c.real(0);
        c.imag(0);
        encoded_value_blinded[i] = c;
    }

    for (int i = 0; i < nb_vals; i++) {
        DTPKC::Cipher dtpkc_value_blinded = receive_dtpkc_cipher();

        vector<long> value_blinded_vec = dtpkc.decrypt_batch(dtpkc_value_blinded);
        vector<double> rescaled_decrypted_value_blinded_vec(dtpkc_nb_slots);                                 // dsl g paike lol

        for (int j = 0; j < dtpkc_nb_slots; j++) {
            rescaled_decrypted_value_blinded_vec[j] = ((double)value_blinded_vec[j]) / dtpkc_scale_factor;
        }

        for (int j = 0; j < dtpkc_nb_slots; j++) {
            {
                complex<double> c;
                c.real(rescaled_decrypted_value_blinded_vec[j]);
                c.imag(0);
                encoded_value_blinded[i * dtpkc_nb_slots + j] = c;
            }
        }
    }

    scheme.encrypt(fhe_rescaled_value_blinded, encoded_value_blinded, n, logp, logq);

    complex<double> *decrypted_blinded = scheme.decrypt(secretKey, fhe_rescaled_value_blinded);

    cout << "wtf:" << endl;
    for (int j = 0; j < n; ++j) {
        cout << decrypted_blinded[j] << ' ';
    }
    cout << " " << endl;

    SerializationUtils::writeCiphertext(fhe_rescaled_value_blinded, "blinded_cipher.txt");

    if (send_file(new_socket, "blinded_cipher.txt")) {
        cout << "Sent the blinded Cipher" << endl;
    } else {
        cout << "ERROR while sending the blinded cipher" << endl;
    }
}

void CSP_PPLR::test_cryptosystem_switching_batch_naive() {
    cryptosystem_switching_batch_naive();

    read_file(new_socket, "fhe_cipher.txt");
    Ciphertext* fhe_cipher = SerializationUtils::readCiphertext("fhe_cipher.txt");

    complex<double> *encoded_value = scheme.decrypt(secretKey, *fhe_cipher);

    cout << "Encoded values:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << encoded_value[i] << ' ';
    }
    cout << " " << endl;
}


void CSP_PPLR::test_cryptosystem_switching_batch_optimized() {
    cryptosystem_switching_batch_optimized();

    read_file(new_socket, "fhe_cipher.txt");
    Ciphertext* fhe_cipher = SerializationUtils::readCiphertext("fhe_cipher.txt");

    complex<double> *encoded_value = scheme.decrypt(secretKey, *fhe_cipher);

    cout << "Encoded values:" << endl;
    for (int i = 0; i < n; ++i) {
        cout << encoded_value[i] << ' ';
    }
    cout << " " << endl;
}