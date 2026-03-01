---
title: "Setup Matrix Synapse Home-server"
date: 2023-06-18T09:16:10.551Z
draft: false
slug: "setup-matrix-synapse-home-server"
description: "Setup Matrix Synapse Home-server Matrix.org community have dedicated themselves to build a platform for communication in a truly \"end-to-end encrypted\" manner. I believe you are here to quickly..."
toc: true
tocBorder: true
images:
  - image-1.png
---
![matrix.org landing page](image-1.png)

Matrix.org community have dedicated themselves to build a platform for communication in a truly “end-to-end encrypted” manner. I believe you are here to quickly dive into the realm of matrix, So let’s get started.

I’ve tried to generalize steps for all machine and operating systems however things can differ. Feel free to go ahead, point out and ask question.

To make this guide more beginner friendly, **I’ve opt to use Ubuntu/Debian** based distribution **for command references**.

## 01: Requirements

1.  **A Machine to host the synapse home-server**  
    This can be a virtual machine or a local machine. I’d recommend going with a virtual machine or a virtual private server but if you have a spare computer then you can go ahead and use it.   
     — For a virtual machine, you can set-up [**Virtual Box**](https://www.virtualbox.org/) on your computer.  
     — For a virtual private server, you can use [**Azure Cloud**](https://azure.microsoft.com/en-in/free/) or [**Amazon AWS**](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc&awsf.Free%20Tier%20Types=*all&awsf.Free%20Tier%20Categories=*all).  
     — For a spare computer, make sure you have stable [**Ubuntu**](https://ubuntu.com/download) operating system or equivalent installed. **I’d recommend you** **to not use Windows** on any of the above type of machine instead go with Linux-based distributions such as Ubuntu, Open-SUSE etc.  
      
    **If you are a student**, you can avail **free Azure Virtual Machine** along with a bundle of other services by entering into [**GitHub Student Developer Pack**](https://education.github.com/pack) or simply get Azure Virtual Machine through [**Microsoft Azure Cloud Student**](https://azure.microsoft.com/en-in/free/students/).  
      
    **If you are a beginner**, please go with Ubuntu Operating system in all cases.
2.  **A domain name  
    **There a lot of ways in which you can get a domain name for yourself.  
    I’d advise you to get a free domain name for learning and testing purposes. You can get a **free domain name** through [**Duck DNS**](http://duckdns.org/) **or** [**Freenom**](http://freenom.com)**.** For paid domain name, you can go ahead and choose any popular and cheap domain name provider.

## 02: Installing Synapse

*   Open a **terminal** or a **console** in your desired machine.   
    For a virtual private server, first you have to connect to it and there are multiple ways however the simplest one for development purpose is by using SSH. You can read or watch other tutorials on this.   
      
    Let’s say for instance if we are using a virtual private server or virtual machine by Azure.  
     — First, go to Home > \[your virtual machine name\]  
     — Second, in the side-bar you will find **Settings** column under which there is an option for **Connect.  
     —** Third, inside **Connect** panel you can select **SSH** option or **RDP** option whichever is convenient for you. Instructions are available in there.
*   Now that we are in our terminal or console. Let’s make sure our systems are up-to-date by directly updating it by typing the following command in our terminal.

```sh
sudo apt update && upgrade
```

*   We will use **pre-built packages** to install synapse as **it is recommended** for most users. You can head to [**this section**](https://matrix-org.github.io/synapse/latest/setup/installation.html#debianubuntu) of Matrix Installation Guide to copy the latest commands that is to be used to install matrix synapse for your respective operating system.  
       
    For Ubuntu/Debian based Operating Systems :  
    Enter the following commands one-by-one in your terminal or console.

```sh
sudo apt install -y lsb-release wget apt-transport-https
```

```sh
sudo wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main" |
    sudo tee /etc/apt/sources.list.d/matrix-org.list
```

```sh
sudo apt update
```

*   After entering the **following** **command,** it shall **ask you to enter your domain-name** for your home-server. You must enter your domain-name which we previously got for ourselves **carefully** and **removing “https://” and “/”** at the end, for example: your domain-name that is to be entered must simply be like _myexampledomain.duckdns.org_

```sh
sudo apt install matrix-synapse-py3
```

*   Now, let’s install some platform-specific requirements. You can head to [**this section**](https://matrix-org.github.io/synapse/latest/setup/installation.html#platform-specific-prerequisites) of Matrix Installation Guide to copy commands to install platform-specific requirements.  
       
    For Ubuntu/Debian based Operating Systems :  
    Enter the following command in your terminal or console.

```sh
sudo apt install build-essential python3-dev libffi-dev \
                     python3-pip python3-setuptools sqlite3 \
                     libssl-dev virtualenv libjpeg-dev libxslt1-dev libicu-dev
```

*   Congratulations. Matrix Synapse is installed. Now it’s time to get our matrix home-server ready to be rolled.

## 03: Installing PostgreSQL

The Official Matrix Installation Guide recommends us to use postgres instead of sqlite as our database system to overcome present and in-future performance issues. So, let’s set it up.

*   Installing low-level postgres library and postgres development files by entering following commands in our terminal.

```sh
sudo apt install libpq5 libpq-dev
```

*   Installing PostgreSQL client library by entering following commands in our terminal. The following command installs necessary tools for us to interact with our database and set-up a user profile named “**postgres**”.

```sh
sudo apt install postgresql postgresql-contrib
```

*   Setting up our database to be used with matrix synapse.  
    Let’s interact with our postgres database by entering the following command that will bash us into our “**postgres**” user profile.

```sh
sudo -u postgres bash
```

*   Let’s create our postgres user. Our **postgres user-name** is “**synapse-user**”. The following command will also prompt you to enter a password for this postgres user. Make sure to enter a strong password and remember it for future use.

```sh
createuser --pwprompt synapse_user
```

*   Let’s create a database for our synapse home-server. Our database name is “**synapse**”. This command is pretty self-explanatory in nature, make sure to read it properly.

```sh
createdb --encoding=UTF8 --locale=C --template=template0 --owner=synapse_user synapse
```

*   Let’s exit from postgres by entering the following command

```sh
exit
```

*   Now, let’s set-up our postgres database for synapse home-server.  
    First, let’s un-comment and edit **listen\_addresses** variable in the file _postgresql.conf_ located at **/etc/postgresql/12/main/postgresql.conf**

```sh
sudo nano /etc/postgresql/12/main/postgresql.conf
```

*   Find the following line and edit it as such:

```txt
#------------------------------------------------------------------------------
# CONNECTIONS AND AUTHENTICATION
#------------------------------------------------------------------------------

# - Connection Settings -

listen_addresses = 'localhost'          # what IP address(es) to listen on;
```

*   Save the edited file using _Ctrl+W_ and then press _Enter_.
*   Second, let’s edit _pg\_hba.conf_ file and add a line to enable password authentication so that “synapse\_user” can connect to the database “synapse”.

```sh
sudo nano /etc/postgresql/12/main/pg_hba.conf
```

*   Add the following line at the end of the file

```conf
local   synapse         synapse_user                            md5
```

*   So that it looks like:

```txt
# Allow replication connections from localhost, by a user with the
# replication privilege.
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            md5
host    replication     all             ::1/128                 md5
local   synapse         synapse_user                            md5
```

*   Third, let’s add **synapse config** of our database to our **homeserver.yaml** file to finish this set-up. You can head to [**this section**](https://matrix-org.github.io/synapse/latest/postgres.html#synapse-config) of Matrix Installation Guide to copy the required config.

```sh
sudo nano /etc/matrix-synapse/homeserver.yaml
```

*   Make sure to delete the following pre-written lines in our _homeserver.yaml_ file:

```sh
database:
  name: sqlite
  args:
    database: /var/lib/matrix-synapse/homeserver.db
```

*   Add the following line and replace <user> with our postgres username which is “synapse\_user” and <pass> with our postgres synapse user password which we enter earlier and <host> with “localhost”.

```sh
database:
  name: psycopg2
  args:
    user: <user>
    password: <pass>
    database: <db>
    host: <host>
    cp_min: 5
    cp_max: 10
```

*   So that our _homeserver.yaml_ file kind of looks like:

```sh
resources:
      - names: [client, federation]
        compress: false
database:
  name: psycopg2
  args:
    user: synapse_user
    password: lmaoded#00
    database: synapse
    host: localhost
    cp_min: 5
    cp_max: 10
log_config: "/etc/matrix-synapse/log.yaml"
media_store_path: /var/lib/matrix-synapse/media
signing_key_path: "/etc/matrix-synapse/homeserver.signing.key"
trusted_key_servers:
  - server_name: "matrix.org"
```

*   This wraps up our database installation and set-up.

## 04: Setting up Reverse Proxy

For simplicity, we will use [**caddy**](https://caddyserver.com/docs/getting-started) which is an open-source web server to set-up our reverse proxy.

*   Please head to [**this section**](https://caddyserver.com/docs/install) of Caddy Installation Guide to copy commands for installation in your respective operating system.  
       
    For Ubuntu/Debian based Operating Systems :  
    Enter the following command one-by-one in your terminal or console.

```sh
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
```

```sh
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
```

```sh
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
```

```sh
sudo apt update
```

```sh
sudo apt install caddy
```

*   After installation, let’s simply **delete** the pre-written config file for our caddy server called _Caddyfile_ located at /etc/caddy/Caddyfile

```sh
sudo rm -rf /etc/caddy/Caddyfile
```

*   Please head to [**this section**](https://matrix-org.github.io/synapse/latest/reverse_proxy.html#caddy-v2) of Matrix Installation Guide to copy the contents for our new Caddyfile.
*   Let’s create a new Caddyfile at /etc/caddy/ by typing the following command:

```sh
sudo touch /etc/caddy/Caddyfile
```

*   Now, let’s edit it and add the required contents which we copied previously from the Matrix Installation Guide.

```sh
sudo nano /etc/caddy/Caddyfile
```

*   Now paste the following contents in that Caddyfile. Replace _matrix.example.com_ with your domain name and _example.com_ to your domain name.

```sh
matrix.example.com {
  reverse_proxy /_matrix/* localhost:8008
  reverse_proxy /_synapse/client/* localhost:8008
  reverse_proxy localhost:8008
}

example.com:8448 {
  reverse_proxy localhost:8008
}
```

*   Setting-up Reverse Proxy using Caddy is done.
*   One last thing to do, is to add registration\_shared\_secret in our _homeserver.yaml_ in case if you ever want to use Matrix Synapse ADMIN API to perform operations.
*   Edit homeserver.yaml using the following command

```sh
sudo nano /etc/matrix-synapse/homeserver.yaml
```

*   Add the following key and replace <salt> with a password/hash generated by any password generator or hash generator.

```yaml
registration_shared_secret: <salt>
```

*   Let’s restart matrix-synapse and related services to check if our home-server setup is done.

```sh
sudo systemctl restart caddy.service
echo "Restarted Caddy Reverse Proxy Service"
sudo systemctl restart postgresql.service
echo "Restarted postgresql Service"
sudo systemctl restart matrix-synapse
echo "Restarted Matrix-synapse entirely"
```

*   Now visit your domain name provider and **change** **_current IP_ of that domain name** to the **IP address of your machine**.  
    For example while using Azure Virtual Machine, you can head to Home > \[Your Virtual Machine Name\] > Networking to **get** **IPv4 address of that machine.**
*   Wait a few minutes for your domain name pointing to your machine IP Address to propagate through DNS.
*   **To confirm that your Matrix Synapse Home-server is active** now, visit your domain-name by entering it into a browser. You should see a static page with Matrix logo and other information.

## 05: Allowing User Registration in home-server

Let’s make sure that our new home-server allow clients _( such as Element.io )_ to register new users to communicate with through our home-server.

*   First, go to [**Google Re-captcha**](https://www.google.com/recaptcha/admin) admin page and sign-in using your google account.
*   Second, go to [**Create**](https://www.google.com/recaptcha/admin/create) part of Google Re-captcha admin portal to register a new site.
*   Third,  
     — Enter _Label_ to identify which site/app/purpose you are using this re-captcha for.  
     — Select _Re-captcha_ type to be **Challenge(v2)  
     —** Add your domain name which you used for home-server  
     — Add domain name of client which you will be using to access your home-server. For example, if I use Element.io, i will add _app.element.io_ in my re-captcha domains.
*   Fourth, Submit and in the next page you will be shown _SITE\_KEY_ and _SECRET\_KEY_ which you can also access through settings in Google Re-captcha admin panel.
*   Fifth, in your terminal enter the following command to edit _homeserver.yaml_ file and add the following lines. Make sure to add your _SITE\_KEY_ inside “ ” in _recaptcha\_public\_key_ and _SECRET\_KEY_ inside “ ” in _recaptcha\_private\_key._

```yaml
enable_registration: true
enable_registration_captcha: true
recaptcha_public_key: ""
recaptcha_private_key: ""
```

*   Sixth, restart matrix-synapse and related services.

```sh
sudo systemctl restart caddy.service
echo "Restarted Caddy Reverse Proxy Service"
sudo systemctl restart postgresql.service
echo "Restarted postgresql Service"
sudo systemctl restart matrix-synapse
echo "Restarted Matrix-synapse entirely"
```

*   Registration should be enabled now. You can go ahead and use any matrix client to access your home-server and create an account on it and then communicate through it.

☕🫡 Now feel free to ask any query. Go ahead, become a part of matrix community. Host, Support or Develop matrix further.

## 06: Appendix

1.  [Element.io Matrix Client](https://app.element.io/)
2.  [Matrix Home-server Configuration Guide](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html)
3.  [Matrix Federation Guide](https://matrix-org.github.io/synapse/latest/federate.html)