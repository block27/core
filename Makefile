RED=\033[0;31m
GRE=\033[0;32m
RES=\033[0m
MAG=\033[0;35m
CYN=\033[0;36m
RL1=\033[0;41m
BL1=\033[0;44m

key_iv:
	@echo "---------------------------------------------------------------------"
	@echo "${MAG}ENV${RES}[${RL1}KEY${RES}]: \t[${GRE}${KEY}${RES}]"
	@echo "${CYN}EXT${RES}[${RL1}KEY${RES}]: \t[${GRE}$(shell cat /var/data/key)${RES}]"
	@echo "${MAG}ENV${RES}[${BL1}IV${RES}]: \t[${GRE}${IV}${RES}]"
	@echo "${CYN}EXT${RES}[${BL1}IV${RES}]: \t[${GRE}$(shell cat /var/data/iv)${RES}]"
	@echo "---------------------------------------------------------------------"

# encrypt_ext: key_iv
# 	@openssl aes-256-cbc -e -nosalt -K ${KEY} -iv ${IV} -in /var/data/pin1 -out /Volumes/BASE1/var/data/pin
# 	@openssl aes-256-cbc -e -nosalt -K ${KEY} -iv ${IV} -in /var/data/pin2 -out /Volumes/BASE2/var/data/pin
# 	@echo "Success!"
#
# decrypt_ext: key_iv
# 	@openssl aes-256-cbc -d -nosalt -K ${KEY} -iv ${IV} -in /Volumes/BASE1/var/data/pin
# 	@echo ""
# 	@openssl aes-256-cbc -d -nosalt -K ${KEY} -iv ${IV} -in /Volumes/BASE2/var/data/pin
# 	@echo ""

run:
	go build && ./bespin

test:
	go test ./... -cover
