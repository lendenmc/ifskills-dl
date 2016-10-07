#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
File: ifskills-dl.py
Author: lendenmc
Date: 2016-10-05
Description: Command line video downloader for learn.infiniteskills.com account
'''

import sys
import os
import re
import json
import io
import getpass
from zipfile import ZipFile, BadZipFile
from contextlib import suppress
from collections import OrderedDict

import requests
from requests.utils import get_netrc_auth
from requests.exceptions import RequestException, ConnectionError
from requests.exceptions import MissingSchema, HTTPError
from bs4 import BeautifulSoup


class LoginError(Exception):
    pass


class LogoutError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class ClearoutError(Exception):
    pass


class DownloadError(Exception):
    pass


class HTMLError(Exception):
    pass


def print_msg(action, resource=None, url=None):
    msg = action
    if resource is not None:
        msg += ": \"{}\"".format(resource)
    print(msg)
    if url is not None:
        print("from url {}".format(url))


def raise_error(error_type, msg, error=None):
    error_msg = "Error: " + msg
    if error is not None:
        print(error_msg, file=sys.stderr)
        raise error_type(error)
    raise error_type(error_msg)


def force_exit(msg, error=None):
    raise_error(SystemExit, msg, error)


class ResponseParser(object):

    def __init__(self, response, error_type, stream=False):
        self.error_type = error_type
        self.action = self.error_type.__name__.rstrip('Error') + ' attempt'
        self.response = response
        if not self.response:
            msg = self.action + " didn't return anything"
            raise_error(self.error_type, msg)
        self.stream = stream
        self.message = self.read_text()
        self.error_msg = self.get_explicit_error()
        self.is_login_error = self.has_error_prefix("Login")
        self.is_clearout_error = self.has_error_prefix("Clearout")
        self.is_authentication_error = self.has_error_prefix("Authentication")

    def read_text(self):
        if self.stream:
            return None
        return self.response.text

    def get_explicit_error(self):
        if self.message and self.message.startswith('error'):
            error_msg = self.message.strip("error::").rstrip('.')
            return error_msg

    def has_error_prefix(self, prefix):
        name = self.error_type.__name__
        return name.startswith(prefix)

    def get_clearout_param(self):
        test_substring = re.compile('clearSession\(\'(\S+)\'\)')
        match = re.search(test_substring, str(self.error_msg))
        if match:
            param = match.group(1)
            return param

    def get_multiple_sessions_error_msg(self):
        test_substring = re.compile('\. If you believe this is an error.+')
        if not re.search(test_substring, str(self.error_msg)):
            return
        # remove browser-dependent part of the error message
        return re.sub(test_substring, '', self.error_msg)

    def test_multiple_sessions_error(self, login_attempts):
        msg = self.get_multiple_sessions_error_msg()
        if msg is None:
            return False
        if not self.is_login_error:
            raise_error(self.error_type, msg)
        clearout_param = self.get_clearout_param()
        if login_attempts > 1 or clearout_param is None:
            advice = "Please manually clear out of any browser session"
            raise LoginError(advice)
        print(msg, file=sys.stderr)
        return clearout_param

    def test_cookies_error(self):
        test_substring = re.compile('.+browser that accepts cookies')
        if re.match(test_substring, str(self.error_msg)):
            msg = "Session aborted for some unexpected reason"
            raise_error(self.error_type, msg)
        return False

    def raise_default_error(self):
        if not self.error_msg:
            raise self.error_type
        elif self.is_login_error or self.is_clearout_error:
            raise self.error_type(self.error_msg)
        else:
            msg = self.action + " failed\n" + self.error_msg
            raise_error(self.error_type, msg)

    @classmethod
    def test_course_title(cls, html, course_id):
        href = '/product.html?sku=' + course_id
        title = html.find('a', {
            'href': href
        })
        if title is None:
            msg = "Authentication attempt failed\n" + \
                "Invalid course id: \"" + course_id + "\""
            raise_error(AuthenticationError, msg)
        return title.contents[0]

    @classmethod
    def test_stream(cls, chunk):
        if type(chunk) is not bytes or chunk.strip().startswith(b'<!DOCTYPE'):
            raise_error(DownloadError, "No streaming file was returned")
        return True


class Session(object):

    errors_without_traceback = [
        AuthenticationError,
        HTMLError,
        DownloadError,
        KeyboardInterrupt,
        HTTPError
    ]

    def __init__(self, session):
        self.session = session
        self.host = "https://learn.infiniteskills.com/"
        self.ajax_headers = self.get_ajax_headers()
        self.login_attempts = 0

    def __enter__(self):
        self.try_login()
        print()
        return self

    def __exit__(self, type, value, traceback):
        if type in self.errors_without_traceback:
            if type is not KeyboardInterrupt:
                print(value, file=sys.stderr)
            print()
            self.try_logout()
            sys.exit(1)
        self.try_logout()

    def try_login(self):
        print("Logging into account")
        try:
            self.login_attempts += 1
            self.startup()
            self.login()
        except (LoginError, RequestException) as e:
            msg = "Cannot log into account"
            force_exit(msg, e)
        except ClearoutError as e:
            msg = "Cannot clear out of all active sessions"
            force_exit(msg, e)
        except KeyboardInterrupt as e:
            raise SystemExit(e)

    def try_logout(self):
        try:
            self.logout()
        except RequestException as e:
            msg = "Cannot log out of account"
            force_exit(msg, e)
        except KeyboardInterrupt:
            print()

    def check_response(self, response, error_type, **kwargs):
        parser = ResponseParser(response, error_type, **kwargs)
        if parser.error_msg:
            self.manage_errors(parser)

    def manage_errors(self, parser):
        login_attempts = self.login_attempts
        clearout_param = parser.test_multiple_sessions_error(login_attempts)
        if clearout_param:
            print("So clearing out of all active sessions")
            self.clearout_browser_sessions(clearout_param)
            print("Trying to log into account again")
            self.try_login()
        else:
            parser.test_cookies_error()
            parser.raise_default_error()

    def clearout_browser_sessions(self, param):
        url = self.host + "ajax/login.html"
        params = {
            'action': 'clear',
            'n': param
        }
        try:
            r = self.session.get(url, headers=self.ajax_headers, params=params)
        except RequestException as e:
            raise ClearoutError(e)
        self.check_response(r, ClearoutError)

    def startup(self):
        url = self.host + "login.html"
        r = self.session.get(url)
        self.check_response(r, LoginError)

    def login(self):
        url = self.host + "ajax/login.html"
        credentials = self.get_credentials()
        r = self.session.post(url, headers=self.ajax_headers, data=credentials)
        self.check_response(r, LoginError)

    def logout(self):
        url = self.host + "login.html"
        params = {
            'action': 'logout'
        }
        print("Logging out of account")
        r = self.session.get(url, params=params)
        self.check_response(r, LogoutError)

    def authenticate(self, course_id):
        url = self.host + "player.html"
        params = {
            'sku': course_id
        }
        print_msg("Authenticating course id", course_id)
        r = self.session.get(url, params=params)
        self.check_response(r, AuthenticationError)
        html = BeautifulSoup(r.content, 'html.parser')
        ResponseParser.test_course_title(html, course_id)
        return r

    def get_credentials(self):
        auth = get_netrc_auth(self.host)
        if auth:
            print("Found netrc credentials")
            username, password = auth
        else:
            username = input("Username: ")
            password = getpass.getpass()
        if not username or not password:
            msg = "Invalid credentials: username and password cannot be blank"
            raise LoginError(msg)
        credentials = {
            'username': username,
            'password': password
        }
        return credentials

    @staticmethod
    def get_ajax_headers():
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
        }
        return headers


class Course(object):

    def __init__(self, id, content, session):
        self.id = id
        self.html = BeautifulSoup(content, 'html.parser')
        self.session = session
        self.title = self.get_title()
        self.resource_host = "http://bitcast-r.v1.iad1.bitgravity.com/"
        self.lectures = self.get_lectures()
        self.sections = self.get_sections()
        self.working_files_id = self.get_working_files_id()
        self.last_skipped = False
        print_msg("Checking into course", self.title)
        print()

    def get_title(self):
        title = ResponseParser.test_course_title(self.html, self.id)
        return title

    @staticmethod
    def format_lecture(raw):
        lecture = re.sub(r'[\n\t]*(\w+): "', r'"\1": "', raw)
        lecture = lecture.replace('\\', '')
        lecture = re.sub(r' "(\w+)" ', r' \"\1\" ', lecture)
        lecture = json.loads(lecture)
        mediaid = lecture['mediaid'].split('^')
        lecture['vid'] = mediaid[0]
        lecture['t'] = mediaid[1]
        lecture['section'] = lecture['description']
        return lecture

    def format_lectures(self, raw):
        lectures = []
        for i, raw_lecture in enumerate(raw):
            lecture = self.format_lecture(raw_lecture)
            lecture['index'] = i
            lectures.append(lecture)
        return lectures

    def get_lectures(self):
        raw_playlist = self.html.find('script', text=re.compile('playlist: '))
        try:
            raw_lectures = re.findall(r'{image:.*?}', raw_playlist.contents[0],
                                      re.DOTALL)
            if len(raw_lectures) == 0:
                raise HTMLError
        except (AttributeError, HTMLError):
            raise_error(HTMLError, "Cannot find any lectures for this course")
        lectures = self.format_lectures(raw_lectures)
        return lectures

    def get_sections(self):
        lectures_sections = [lecture['section'] for lecture in self.lectures]
        sections = list(OrderedDict.fromkeys(lectures_sections))
        return sections

    @staticmethod
    def sanitize_filename(name):
        name = re.sub(r'\/', '', name)
        return name

    @staticmethod
    def makedir(dirname):
        if not os.path.exists(dirname):
            os.makedirs(dirname)

    def makedirs(self):
        course_dirname = self.sanitize_filename(self.title)
        self.makedir(course_dirname)
        for section in self.sections:
            section_dirname = self.sanitize_filename(section)
            self.makedir(course_dirname + '/' + section_dirname)

    def fetch_string(self, url, params, error_msg, attempts=1):
        headers = self.session.ajax_headers
        fetched = self.session.session.get(url, headers=headers, params=params)
        fetched.raise_for_status()
        self.session.check_response(fetched, AuthenticationError)
        if fetched.text.startswith('<!DOCTYPE html>'):
            if attempts > 2:
                raise_error(AuthenticationError, error_msg)
            attempts += 1
            return self.fetch_string(url, params, error_msg, attempts)
        return fetched.text

    # output format: '?e=1672341893&h=8d8fba20cd6a39739114e23464be721&pos=0'
    def authenticate(self, lecture):
        url = self.session.host + "ajax/player.html"
        params = {key: lecture[key] for key in ['t', 'index', 'file', 'vid']}
        params['action'] = 'hash'
        if self.last_skipped:
            print()
        self.last_skipped = False
        print_msg("Authenticating lecture", lecture['title'])
        error_msg = "No authentication params were returned"
        auth_params = self.fetch_string(url, params, error_msg)
        return auth_params

    def make_filename(self, lecture):
        short_filename = lecture['file'].rsplit('/', 1)[-1]
        name, extension = os.path.splitext(short_filename)
        lecture_title = self.sanitize_filename(lecture['title'])
        filename = name + '. ' + lecture_title + extension
        title = self.sanitize_filename(self.title)
        section = self.sanitize_filename(lecture['section'])
        dirname = title + '/' + section + '/'
        return dirname + filename

    def test_file(self, local_file):
        if os.path.isfile(local_file):
            print_msg("Skipping download of existing file", local_file)
            self.last_skipped = True
            return
        return True

    @staticmethod
    def stream(streaming_file, local_file):
        sf = streaming_file
        try:
            with open(local_file, 'wb') as f:
                for i, chunk in enumerate(sf.iter_content(chunk_size=1024)):
                    if i == 0:
                        ResponseParser.test_stream(chunk)
                    if chunk:
                        f.write(chunk)
        except (KeyboardInterrupt, DownloadError) as e:
            with suppress(FileNotFoundError):
                os.remove(local_file)
            raise e
        except FileNotFoundError as e:
            raise_error(DownloadError, re.sub(r'\[.+\] ', '', str(e)))

    def fetch_url(self, lecture):
        url = self.resource_host + "infiniteskills/"
        url += lecture['file'].split('/', 3)[3]
        auth_params = self.authenticate(lecture)
        url += auth_params
        return url

    def download(self, url):
        try:
            file = requests.get(url, stream=True)
        except MissingSchema:
            raise_error(DownloadError, "Invalid url")
        except ConnectionError:
            raise_error(DownloadError, "Failed to establish a new connection")
        file.raise_for_status()
        self.session.check_response(file, DownloadError, stream=True)
        return file

    def get_working_files_id(self):
        working_files = self.html.find('form', {'id': 'filedownload'})
        if working_files is not None:
            working_files_id = working_files.option['value']
            return working_files_id

    def test_working_files(self):
        if self.working_files_id is None:
            print("No working files for this course")
            return
        wf_name = self.title + " - " + "Working Files"
        if os.path.exists(self.title + '/' + wf_name):
            print("Working files already downloaded for this course")
            return
        return True

    def fetch_zip_url(self):
        url = self.session.host + "ajax/history.html"
        wfid = self.working_files_id
        params = {
            'event': 'file',
            'id': wfid
        }
        print_msg("Authenticating course working files id", wfid)
        error_msg = "No zip file url was returned"
        zip_url = self.fetch_string(url, params, error_msg)
        return zip_url

    def stream_working_files(self, zip_file):
        try:
            with ZipFile(io.BytesIO(zip_file.content)) as myzip:
                myzip.extractall(self.title)
        except BadZipFile:
            raise_error(DownloadError, "No zip file was returned")


if __name__ == "__main__":
    course_ids = sys.argv[1:]
    if len(course_ids) == 0:
        force_exit("Please provide at least one course id as argument")
    with requests.Session() as s, Session(s) as session:
        for course_id in course_ids:
            course_content = session.authenticate(course_id).content
            course = Course(course_id, course_content, session)
            course.makedirs()
            if course.test_working_files():
                zip_url = course.fetch_zip_url()
                msg = "Downloading course working files"
                print_msg(msg, url=zip_url.strip('\n'))
                zip_file = course.download(zip_url)
                course.stream_working_files(zip_file)
            print()
            for lecture in course.lectures:
                local_file = course.make_filename(lecture)
                if course.test_file(local_file) is None:
                    continue
                url = course.fetch_url(lecture)
                print_msg("Downloading file", local_file, url=url)
                streaming_file = course.download(url)
                course.stream(streaming_file, local_file)
                print()
            if course.last_skipped:
                print()
            print_msg("Done with course " + course_id, course.title)
            print()
