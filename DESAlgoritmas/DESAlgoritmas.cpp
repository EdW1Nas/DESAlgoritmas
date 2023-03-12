#include <iostream>
#include <string>
#include <cryptlib.h>
#include <cstdlib>
#include <des.h>
#include <filters.h>
#include <modes.h>
#include <fstream>
using namespace std;
using namespace CryptoPP;

int main()
{
	string tekstoIvedimas, password, teksoIsvedimas;
	int ivedimasPasirinkimas, sifrPasirinkimas, desPasirinkimas;

	cout << "Pasirinkite teksto ivedimo buda" << endl;
	cout << "1. Ivesti teksta i konsole" << endl;
	cout << "2. Gauti teksta is failo" << endl;
	cin >> ivedimasPasirinkimas;
	cin.ignore();

	if (ivedimasPasirinkimas == 1)
	{
		cout << "Iveskite teksta kuri norite sifruoti/desifruoti" << endl;
		getline(cin, tekstoIvedimas);
	}

	else if (ivedimasPasirinkimas == 2)
	{
		string failoVardas;
		cout << "Iveskite tekstinio faila pilna pavadinima (su .txt)" << endl;
		cin >> failoVardas;

		cin.ignore(numeric_limits<streamsize>::max(), '\n');

		ifstream file(failoVardas);
		if (file.is_open())
		{
			getline(file, tekstoIvedimas);
			file.close();
		}
		else
		{
			cout << "Klaida" << endl;
			cin.ignore();
		}
	}
	else { cout << "Klaida" << endl; return 1; };

	cout << "Iveskite slaptazodi" << endl;
	getline(cin, password);

	cout << "Iveskite parinkti: " << endl;
	cout << "1. Sifruoti" << endl;
	cout << "2. Desifruoti" << endl;
	cin >> sifrPasirinkimas;

	cout << "Pasirinkite DES parinkti: " << endl;
	cout << "1. ECB" << endl;
	cout << "2. CBC" << endl;
	cout << "3. CFB" << endl;
	cout << "4. OFB" << endl;
	cout << "5. CTR" << endl;
	cin >> desPasirinkimas;

	try
	{
		CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption encrypt_ecb;
		CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption decrypt_ecb;
		CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption encrypt_cbc;
		CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption decrypt_cbc;
		CryptoPP::CFB_Mode<CryptoPP::DES>::Encryption encrypt_cfb;
		CryptoPP::CFB_Mode<CryptoPP::DES>::Decryption decrypt_cfb;
		CryptoPP::OFB_Mode<CryptoPP::DES>::Encryption encrypt_ofb;
		CryptoPP::OFB_Mode<CryptoPP::DES>::Decryption decrypt_ofb;
		CryptoPP::CTR_Mode<CryptoPP::DES>::Encryption encrypt_ctr;
		CryptoPP::CTR_Mode<CryptoPP::DES>::Decryption decrypt_ctr;

		//ECB
		if (desPasirinkimas == 1)
		{
			if (sifrPasirinkimas == 1)
			{
				encrypt_ecb.SetKey((byte*)password.c_str(), password.length());

				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(encrypt_ecb, new StringSink(teksoIsvedimas)));
			}
			else if (sifrPasirinkimas == 2)
			{
				decrypt_ecb.SetKey((byte*)password.c_str(), password.length());
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(decrypt_ecb, new StringSink(teksoIsvedimas)));
			}
			else
			{
				cout << "Klaida" << endl;
				return 1;
			}
		}

		// CBC
		else if (desPasirinkimas == 2)
		{
			byte iv[CryptoPP::DES::BLOCKSIZE];
			memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

			if (sifrPasirinkimas == 1)
			{
				encrypt_cbc.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(encrypt_cbc, new StringSink(teksoIsvedimas)));
			}
			else if (sifrPasirinkimas == 2)
			{
				decrypt_cbc.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(decrypt_cbc, new StringSink(teksoIsvedimas)));
			}
			else
			{
				cout << "Klaida" << endl;
				return 1;
			}
		}

		// CFB
		else if (desPasirinkimas == 3)
		{
			byte iv[CryptoPP::DES::BLOCKSIZE];
			memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

			if (sifrPasirinkimas == 1)
			{
				encrypt_cfb.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(encrypt_cfb, new StringSink(teksoIsvedimas)));
			}
			else if (sifrPasirinkimas == 2)
			{
				decrypt_cfb.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(decrypt_cfb, new StringSink(teksoIsvedimas)));
			}
			else
			{
				cout << "Klaida" << endl;
				return 1;
			}
		}

		// OFB
		else if (desPasirinkimas == 4)
		{
			byte iv[CryptoPP::DES::BLOCKSIZE];
			memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

			if (sifrPasirinkimas == 1)
			{
				encrypt_ofb.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(encrypt_ofb, new StringSink(teksoIsvedimas)));
			}
			else if (sifrPasirinkimas == 2)
			{
				decrypt_ofb.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(decrypt_ofb, new StringSink(teksoIsvedimas)));
			}
			else
			{
				cout << "Klaida" << endl;
				return 1;
			}
		}

		// CTR
		else if (desPasirinkimas == 5)
		{
			byte iv[CryptoPP::DES::BLOCKSIZE];
			memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

			if (sifrPasirinkimas == 1)
			{
				encrypt_ctr.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(encrypt_ctr, new StringSink(teksoIsvedimas)));
			}
			else if (sifrPasirinkimas == 2)
			{
				decrypt_ctr.SetKeyWithIV((byte*)password.c_str(), password.length(), iv);
				StringSource(tekstoIvedimas, true, new StreamTransformationFilter(decrypt_ctr, new StringSink(teksoIsvedimas)));
			}
			else
			{
				cout << "Klaida" << endl;
				return 1;
			}
		}
		else
		{
			cout << "Klaida" << endl;
			return 1;
		}

		cout << "   Ivestis:   " << tekstoIvedimas << endl;
		cout << "Rezultatas:  " << teksoIsvedimas << endl;

		if (ivedimasPasirinkimas == 2)
		{
			fstream isvedimasFile;
			isvedimasFile.open("output.txt", ios::out);

			if (isvedimasFile.is_open())
			{
				isvedimasFile << teksoIsvedimas << endl;
				isvedimasFile.close();
				cout << "Rezultatas isvestas i tekstini faila 'output.txt'" << endl;
			}
		}
	}

	catch (const CryptoPP::Exception& e)
	{
		cerr << "Klaida: " << e.what() << endl;
		return 1;
	}

	return 0;
}

