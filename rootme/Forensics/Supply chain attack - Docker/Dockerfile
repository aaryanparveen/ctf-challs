FROM debian:latest

ENV SQL_USER="myuser"
ENV SQL_PASS="G00d_P4ssw0rd_sH54Xe7Mz47jMjj"
ENV SQL_DATABASE="myD4t4b4s3"
ENV SQL_TABLE="awesome_table"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt -y update && \ 
    apt -y install default-mysql-server default-mysql-client

RUN sed -i 's/^.*bind-address.*=.*$/bind-address = 0.0.0.0/g' /etc/mysql/mariadb.conf.d/50-server.cnf

RUN service mysql start;\
    mysql -u root -e "CREATE USER '${SQL_USER}'@'%' IDENTIFIED BY '${SQL_PASS}'; UPDATE mysql.user set plugin = 'mysql_native_password' WHERE User = '${SQL_USER}'; GRANT ALL PRIVILEGES ON *.* TO '${SQL_USER}'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;" ;\
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS '${SQL_DATABASE}'; SET GLOBAL local_infile = true;" ;\
    mysql -u root -e "USE '${SQL_DATABASE}'; CREATE TABLE IF NOT EXISTS '${SQL_TABLE}' (a varchar(255));"

EXPOSE 3306

# Only without docker-compose
# CMD ["mysqld"]