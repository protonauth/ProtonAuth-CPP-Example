#pragma once

#ifndef c_auth_i
#define c_auth_i

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/ccm.h>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <atlsecurity.h> 
#include <windows.h>
#include <string>
#include <ctime>
#include <vector>

#pragma comment(lib, "rpcrt4.lib")

#include "pe_xor.hpp"

namespace proton {

	class encryption {
	public:
		static std::string encrypt_string(const std::string& plain_text, const std::string& key, const std::string& iv) {
			std::string cipher_text;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
				encryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

				CryptoPP::StringSource encryptor(plain_text, true,
					new CryptoPP::StreamTransformationFilter(encryption,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(cipher_text),
							false
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				MessageBoxA(0, ex.what(), "pAuth", MB_ICONERROR);
				exit(0);
			}
			return cipher_text;
		}

		static std::string decrypt_string(const std::string& cipher_text, const std::string& key, const std::string& iv) {
			std::string plain_text;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
				decryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

				CryptoPP::StringSource decryptor(cipher_text, true,
					new CryptoPP::HexDecoder(
						new CryptoPP::StreamTransformationFilter(decryption,
							new CryptoPP::StringSink(plain_text)
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				MessageBoxA(0, p_xor("Invalid API/Encryption key"), "pAuth", MB_ICONERROR);
				exit(0);
			}
			return plain_text;
		}

		static std::string sha256(const std::string& plain_text) {
			std::string hashed_text;
			CryptoPP::SHA256 hash;

			try {
				CryptoPP::StringSource hashing(plain_text, true,
					new CryptoPP::HashFilter(hash,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(hashed_text),
							false
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				MessageBoxA(0, ex.what(), "pAuth", MB_ICONERROR);
				exit(0);
			}

			return hashed_text;
		}

		static std::string hex_encode(const std::string& plain_text) {
			std::string encoded_text;

			try {
				CryptoPP::StringSource encoding(plain_text, true,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(encoded_text),
						false
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				MessageBoxA(0, ex.what(), "pAuth", MB_ICONERROR);
				exit(0);
			}

			return encoded_text;
		}

		static std::string hex_decode(const std::string& encoded_text) {
			std::string out;

			try{
				CryptoPP::StringSource decoding(encoded_text, true, 
					new CryptoPP::HexDecoder(
						new CryptoPP::StringSink(out)
						)
					);
			}
			catch (CryptoPP::Exception& ex){
				MessageBoxA(0, ex.what(), "pAuth", MB_ICONERROR);
				exit(0);
			}

			return out;
		}

		static std::string iv_key() {
			UUID uuid = { 0 };
			std::string guid;

			::UuidCreate(&uuid);

			RPC_CSTR szUuid = NULL;
			if (::UuidToStringA(&uuid, &szUuid) == RPC_S_OK)
			{
				guid = (char*)szUuid;
				::RpcStringFreeA(&szUuid);
			}

			return guid.substr(0, 8);
		}

		static std::string encrypt(std::string message, std::string enc_key, std::string iv) {
			enc_key = sha256(enc_key).substr(0, 32);

			iv = sha256(iv).substr(0, 16);
			
			return encrypt_string(message, enc_key, iv);
		}

		static std::string decrypt(std::string message, std::string enc_key, std::string iv) {
			enc_key = sha256(enc_key).substr(0, 32);

			iv = sha256(iv).substr(0, 16);

			return decrypt_string(message, enc_key, iv);
		}
	};

	class utils {
	public:
		static std::vector<std::string> split(const std::string& str, const char separator)
		{
			std::vector<std::string> output;
			std::string::size_type prev_pos = 0, pos = 0;

			while ((pos = str.find(separator, pos)) != std::string::npos)
			{
				auto substring(str.substr(prev_pos, pos - prev_pos));
				output.push_back(substring);
				prev_pos = ++pos;
			}

			output.push_back(str.substr(prev_pos, pos - prev_pos));
			return output;
		}

		static std::string get_hwid() { // get user SID
			ATL::CAccessToken accessToken;
			ATL::CSid currentUserSid;
			if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
				accessToken.GetUser(&currentUserSid))
				return std::string(CT2A(currentUserSid.Sid()));
		}

		static std::time_t string_to_timet(std::string timestamp) {
			auto cv = strtol(timestamp.c_str(), NULL, 10); // long

			return (time_t)cv;
		}

		static std::tm timet_to_tm(time_t timestamp) {
			std::tm context;

			localtime_s(&context, &timestamp);

			return context;
		}
	};

	std::string api_endpoint = p_xor("https://protonauth.xyz/api/handler.php");

	std::string user_agent = p_xor("Mozilla pAuth");

	class api {
	public:
		std::string program_version, program_key, api_key;

		api(std::string version, std::string program_key, std::string api_key, bool show_messages = true) 
			: program_version(version), program_key(program_key), api_key(api_key), show_messages(show_messages) {}

		void init() {
			session_iv = encryption::iv_key();

			auto init_iv = encryption::sha256(session_iv); // can be changed to whatever you want
			auto post_data =
				p_xor("version=") + encryption::encrypt(program_version, api_key, init_iv) +
				p_xor("&session_iv=") + encryption::encrypt(session_iv, api_key, init_iv) +
				p_xor("&api_version=") + encryption::encrypt("1.2", api_key, init_iv) +
				p_xor("&program_key=") + encryption::hex_encode(program_key) +
				p_xor("&init_iv=") + init_iv;

			auto response = do_request(p_xor("init"), post_data);

			if (response == p_xor("program_doesnt_exist")) {
				MessageBoxA(0, p_xor("The program key you tried to use doesn't exist"), "pAuth", MB_ICONERROR);

				return;
			}

			response = encryption::decrypt(response, api_key, init_iv);

			auto decoded_response = response_decoder.parse(response);

			if (!decoded_response[p_xor("success")])
				MessageBoxA(0, std::string(decoded_response[p_xor("message")]).c_str(), "pAuth", MB_ICONERROR);

			auto response_data = utils::split(decoded_response[p_xor("response")], '|');

			if (response_data[0] == p_xor("wrong_version")) {
				ShellExecuteA(0, "open", response_data[1].c_str(), 0, 0, SW_SHOWNORMAL);
				//only for windows ^

				return;
			}

			is_initialized = true;

			session_iv += response_data[1];

			session_id = response_data[2];
		}

		bool login(std::string username, std::string password, std::string hwid = "default") {
			if (hwid == "default") hwid = utils::get_hwid();

			if (!is_initialized) {
				MessageBoxA(0, p_xor("The program wasn't initialized"), "pAuth", MB_ICONERROR);

				return false;
			}

			auto post_data =
				p_xor("username=") + encryption::encrypt(username, api_key, session_iv) +
				p_xor("&password=") + encryption::encrypt(password, api_key, session_iv) +
				p_xor("&hwid=") + encryption::encrypt(hwid, api_key, session_iv) +
				p_xor("&sessid=") + encryption::hex_encode(session_id);

			auto response = do_request(p_xor("login"), post_data);

			response = encryption::decrypt(response, api_key, session_iv);

			auto decoded_response = response_decoder.parse(response);

			logged_in = decoded_response[p_xor("success")];

			if (!logged_in && show_messages)
			{
				// MessageBoxA(0, std::string(decoded_response[p_xor("message")]).c_str(), "pAuth", MB_ICONERROR);
			}
			else if(logged_in)
				load_user_data(decoded_response[p_xor("user_data")]);

			return logged_in;
		}

		#define register _register

		bool register(std::string username, std::string email, std::string password, std::string token, std::string hwid = "default") {
			if (hwid == "default") hwid = utils::get_hwid();

			if (!is_initialized) {
				MessageBoxA(0, p_xor("The program wasn't initialized"), "pAuth", MB_ICONERROR);

				return false;
			}

			auto values =
				p_xor("username=") + encryption::encrypt(username, api_key, session_iv) +
				p_xor("&email=") + encryption::encrypt(email, api_key, session_iv) +
				p_xor("&password=") + encryption::encrypt(password, api_key, session_iv) +
				p_xor("&token=") + encryption::encrypt(token, api_key, session_iv) +
				p_xor("&hwid=") + encryption::encrypt(hwid, api_key, session_iv) +
				p_xor("&sessid=") + encryption::hex_encode(session_id);

			auto response = do_request(p_xor("register"), values);

			response = encryption::decrypt(response, api_key, session_iv);

			auto decoded_response = response_decoder.parse(response);

			if (!decoded_response[p_xor("success")] && show_messages)
				MessageBoxA(0, std::string(decoded_response[p_xor("message")]).c_str(), "pAuth", MB_ICONERROR);

			return decoded_response[p_xor("success")];
		}

		bool activate(std::string username, std::string token) {
			if (!is_initialized) {
				MessageBoxA(0, p_xor("The program wasn't initialized"), "pAuth", MB_ICONERROR);

				return false;
			}

			auto post_data =
				p_xor("username=") + encryption::encrypt(username, api_key, session_iv) +
				p_xor("&token=") + encryption::encrypt(token, api_key, session_iv) +
				p_xor("&sessid=") + encryption::hex_encode(session_id);

			auto response = do_request(p_xor("activate"), post_data);

			response = encryption::decrypt(response, api_key, session_iv);

			auto decoded_response = response_decoder.parse(response);

			if (!decoded_response[p_xor("success")] && show_messages)
				MessageBoxA(0, std::string(decoded_response[p_xor("message")]).c_str(), "pAuth", MB_ICONERROR);

			return decoded_response[p_xor("success")];
		}

		bool all_in_one(std::string token, std::string hwid = "default") {
			if (hwid == "default") hwid = utils::get_hwid();

			if (login(token, token, hwid))
				return true;

			else if (register(token, token + p_xor("@email.com"), token, token, hwid)) {
				exit(0);
				return true;
			}

			return false;
		}

		std::vector<unsigned char> file(std::string file_name, std::string hwid = "default"){
			if(hwid == "default") hwid = utils::get_hwid();

			auto to_uc_vector = [](std::string value){
				return std::vector<unsigned char>(value.data(), value.data() + value.length() + 1);
			};

			if(!is_initialized){
				MessageBoxA(0, p_xor("The program wasn't initialized"), "pAuth", MB_ICONERROR);

				return to_uc_vector(p_xor("not_initialized"));
			}

			if(!logged_in){
				MessageBoxA(0, p_xor("You can only grab server sided files after being logged in."), "pAuth", MB_ICONERROR);

				return to_uc_vector(p_xor("not_logged_in"));
			}

			auto post_data =
				p_xor("file_name") + encryption::encrypt(file_name, api_key, session_iv) +
				p_xor("&sessid=") + encryption::hex_encode(session_id);

			auto response = do_request(p_xor("file"), post_data);

			response = encryption::decrypt(response, api_key, session_iv);

			auto decoded_response = response_decoder.parse(response);

			if (!decoded_response[p_xor("success")] && show_messages)
                MessageBoxA(0, std::string(decoded_response[p_xor("message")]).c_str(), "pAuth", MB_ICONERROR);
			
			auto file = encryption::hex_decode(decoded_response[p_xor("response")]);

			return to_uc_vector(file);
		}

		std::string var(std::string var_name, std::string hwid = "default") {
			if (hwid == "default") hwid = utils::get_hwid();

			if (!is_initialized) {
				MessageBoxA(0, p_xor("The program wasn't initialized"), "pAuth", MB_ICONERROR);

				return p_xor("not_initialized");
			}

			if (!logged_in) {
				MessageBoxA(0, p_xor("You can only grab server sided variables after being logged in."), "pAuth", MB_ICONERROR);

				return p_xor("not_logged_in");
			}

			auto post_data =
				p_xor("var_name=") + encryption::encrypt(var_name, api_key, session_iv) +
				p_xor("&sessid=") + encryption::hex_encode(session_id);

			auto response = do_request(p_xor("var"), post_data);

			response = encryption::decrypt(response, api_key, session_iv);

			auto decoded_response = response_decoder.parse(response);

			if (!decoded_response[p_xor("success")] && show_messages)
				MessageBoxA(0, std::string(decoded_response[p_xor("message")]).c_str(), "pAuth", MB_ICONERROR);

			return decoded_response[p_xor("response")];
		}

		void log(std::string message) {
			if (user_data.username.empty()) user_data.username = "NONE";

			if (!is_initialized) {
				MessageBoxA(0, p_xor("The program wasn't initialized"), "pAuth", MB_ICONERROR);

				return;
			}

			std::string post_data =
				p_xor("username=") + encryption::encrypt(user_data.username, api_key, session_iv) +
				p_xor("&message=") + encryption::encrypt(message, api_key, session_iv) +
				p_xor("&sessid=") + encryption::hex_encode(session_id);

			do_request(p_xor("log"), post_data);
		}

		class user_data_class {
		public:
			std::string username;
			std::string email;
			std::tm expires;
			std::string var;
			int rank;
		};

		user_data_class user_data;

	private:
		bool show_messages, is_initialized, logged_in;

		std::string session_id, session_iv;

		static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
			((std::string*)userp)->append((char*)contents, size * nmemb);
			return size * nmemb;
		}

		static std::string do_request(std::string type, std::string post_data) {
			CURL* c_url = curl_easy_init();

			if(!c_url)
				return "null";

			std::string to_return;

			curl_easy_setopt(c_url, CURLOPT_URL, std::string(api_endpoint + "?type=" + type).c_str());
			curl_easy_setopt(c_url, CURLOPT_USERAGENT, user_agent.c_str());

			curl_easy_setopt(c_url, CURLOPT_NOPROXY, "protonauth.xyz");

			curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYPEER, 0);
			curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYHOST, 0);

			curl_easy_setopt(c_url, CURLOPT_PINNEDPUBLICKEY, p_xor("sha256//vDK72uL1DKstyvrTxOkGz2sXdMsU8IcWSVR8cCWz7I4="));

			curl_easy_setopt(c_url, CURLOPT_POSTFIELDS, post_data.c_str());

			curl_easy_setopt(c_url, CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(c_url, CURLOPT_WRITEDATA, &to_return);

			auto code = curl_easy_perform(c_url);

			if(code != CURLE_OK)
				MessageBoxA(0, curl_easy_strerror(code), 0, MB_ICONERROR);

			return to_return;
		}

		class user_data_structure {
		public:
			std::string username;
			std::string email;
			std::string expires;
			std::string var;
			int rank;
		};

		void load_user_data(nlohmann::json data) {
			user_data.username = data[p_xor("username")];

			user_data.email = data[p_xor("email")];

			user_data.expires = utils::timet_to_tm(
				utils::string_to_timet(data[p_xor("expires")])
			);

			user_data.var = data[p_xor("var")];

			user_data.rank = data[p_xor("rank")];
		}
		
		nlohmann::json response_decoder;
	};
}


#endif
