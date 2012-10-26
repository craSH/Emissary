#!/usr/bin/env python

from psycopg2 import *
from datetime import datetime
from hashlib import sha256


class logData:
    """ Simply store request and responsne data and let the caller know if we have that data before logging"""

    def __init__(self):
        self.request_data = ""
        self.request_time = ""

        self.response_data = ""
        self.response_time = ""

    def has_request(self):
        if(self.request_data and self.request_time):
            return True
        else:
            return False

    def has_response(self):
        if(self.response_data and self.response_time):
            return True
        else:
            return False

    def has_all(self):
        if(self.has_request() and self.has_response()):
            return True
        else:
            return False

    def clear_request(self):
        self.request_data = ""
        self.request_time = ""

    def clear_response(self):
        self.response_data = ""
        self.response_time = ""

    def clear_all(self):
        self.clear_request()
        self.clear_response()

class postgresLogger:

    def __init__(self, dbhost, dbname, dbuser, dbpass):
        self.connection = connect("dbname='" + dbname + "' user='" + dbuser + "' host='" + dbhost + "' password='" + dbpass + "'")
        self.curs = self.connection.cursor()
        self.run_number = 0
        self.log_id_num = 0


    def log_run_info(self, company_name, product_name, notes=''):
        if(not (isinstance(company_name, str))):
            raise TypeError, "company_name must be of type string"
        if(not (isinstance(product_name, str))):
            raise TypeError, "product_name must be of type string"
        if(not (isinstance(notes, str))):
            raise TypeError, "notes must be of type string"

        table = "fuzzdata.run_info"
        columns = "run_number, run_starttime, company_name, product_name, notes"
        #          bigserial,  timestamp notz, char varying, char varying, char varying

        values_insert = { 'run_starttime':postgres_datetime_ms(), 'company_name':company_name, 'product_name':product_name, 'notes':notes }
        statement_lock = "LOCK " + table + " IN EXCLUSIVE MODE"
        statement_insert = "INSERT INTO " + table + " (" + columns + ") VALUES ( DEFAULT, %(run_starttime)s, %(company_name)s, %(product_name)s, %(notes)s )"
        statement_select = "SELECT run_number FROM " + table + " ORDER BY run_number DESC LIMIT 1"

        try:
            # Lock the table, so we get the proper run number back
            self.curs.execute(statement_lock)
            # Insert our data
            self.curs.execute(statement_insert, values_insert)
            # Get our run number
            self.curs.execute(statement_select)
            self.run_number = self.curs.fetchone()[0];
            # Commit and release the table lock
        finally:
            self.connection.commit()

        return(self.run_number)

    #def log_iteration_data(self, request_data, response_data, request_time):
    def log_iteration_data(self, logdata):
        #if(not logdata.has_all()):
        #    raise Exception, "logdata object doesn't have all needed items for logging!"
        if(not (isinstance(self.run_number, int) or isinstance(self.run_number, long))):
            raise TypeError, "run_number must be of type int or long"
        if(not (isinstance(logdata.request_data, str))):
            raise TypeError, "request_data must be of type string"
        if(not (isinstance(logdata.response_data, str))):
            raise TypeError, "response_data must be of type string"
        if(not (isinstance(logdata.request_time, str))):
            raise TypeError, "request_time must be of type string"

        # Binarify (Postgres) data which is to be stored as a byte array
        # Request data
        request_digest = Binary(digest_data(logdata.request_data))
        request_data = Binary(logdata.request_data)
        if(not logdata.request_time):
            request_time = postgres_datetime_ms()
        else:
            request_time = logdata.request_time

        # Response data
        response_digest = Binary(digest_data(logdata.response_data))
        response_data = Binary(logdata.response_data)
        if(not logdata.response_time):
            response_time = postgres_datetime_ms()
        else:
            response_time = logdata.response_time

        table = "fuzzdata.log_data"
        columns = "id, run_number, request_data, request_digest, response_data, response_digest, request_time"
        #   bigserial, bigint,     bytea,        bytea,          bytea,         bytea,           timestamp notz

        values_insert = { 'run_number':self.run_number, 'request_data':request_data, 'request_digest':request_digest, 'response_data':response_data, 'response_digest':response_digest, 'request_time':request_time }
        statement_lock = "LOCK " + table + " IN EXCLUSIVE MODE"
        statement_insert = "INSERT INTO " + table + " (" + columns + ") VALUES ( DEFAULT, %(run_number)s, %(request_data)s, %(request_digest)s, %(response_data)s, %(response_digest)s, %(request_time)s )"
        statement_select = "SELECT id FROM " + table + " ORDER BY id DESC LIMIT 1"

        try:
            # Lock the table, so we get the proper run number back
            self.curs.execute(statement_lock)
            # Insert our data
            self.curs.execute(statement_insert, values_insert)
            # Get our log ID number
            self.curs.execute(statement_select)
            self.log_id_num = self.curs.fetchone()[0];
        finally:
            # Commit and release the table lock
            self.connection.commit()

        return(self.log_id_num)

def postgres_datetime_ms():
    """Return a Postgres DateTime object that has microsecond resolution. Move to a toolbox library later"""
    now = datetime.now()
    timestamp = Timestamp(now.year, now.month, now.day, now.hour, now.minute, now.second, None)
    timestamp = str(timestamp).strip("'")
    return "'" + timestamp + "." + str(now.microsecond) + "'"

def digest_data(data):
    """Simply return the SHA256 of supplied data (returned in binary, not hex)"""
    return sha256(data).hexdigest()
