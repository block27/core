RED=\033[0;31m
GRE=\033[0;32m
RES=\033[0m

key_iv:
	@echo "---------------------------------------------------------------------"
	@echo "ENV[KEY]: \t[${GRE}${KEY}${RES}]"
	@echo "EXT[KEY]: \t[${GRE}$(shell cat /var/data/key)${RES}]"
	@echo "ENV[IV]: \t[${GRE}${IV}${RES}]"
	@echo "EXT[IV]: \t[${GRE}$(shell cat /var/data/iv)${RES}]"
	@echo "---------------------------------------------------------------------"

encrypt_ext: key_iv
	@openssl aes-256-cbc -e -nosalt -K ${KEY} -iv ${IV} -in /var/data/pin1 -out /Volumes/BASE1/var/data/pin
	@openssl aes-256-cbc -e -nosalt -K ${KEY} -iv ${IV} -in /var/data/pin2 -out /Volumes/BASE2/var/data/pin
	@echo "Success!"

decrypt_ext: key_iv
	@openssl aes-256-cbc -d -nosalt -K ${KEY} -iv ${IV} -in /Volumes/BASE1/var/data/pin
	@echo ""
	@openssl aes-256-cbc -d -nosalt -K ${KEY} -iv ${IV} -in /Volumes/BASE2/var/data/pin
	@echo ""
