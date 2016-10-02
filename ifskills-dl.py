#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import re
import json
import io
import getpass
from zipfile import ZipFile
from contextlib import suppress
from collections import OrderedDict

import requests
from requests.utils import get_netrc_auth
from requests.exceptions import RequestException
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


class ResponseParser(object):

    error_prefix = "Error: "

    def __init__(self, response, error_type, stream=False):
        self.error_type = error_type
        self.action = self.error_prefix + \
            self.error_type.__name__.rstrip('Error') + \
            ' attempt'
        self.response = response
        if not self.response:
            raise self.error_type(self.action + " didn't return anything")
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
            raise self.error_type(self.error_prefix + msg)
        clearout_param = self.get_clearout_param()
        if login_attempts > 1 or clearout_param is None:
            advice = "Please manually clear out of any browser session"
            raise LoginError(advice)
        print(msg, file=sys.stderr)
        return clearout_param

    def test_cookies_error(self):
        test_substring = re.compile('.+browser that accepts cookies')
        if re.match(test_substring, str(self.error_msg)):
            msg = self.error_prefix + \
                "Session aborted for some unexpected reason"
            raise self.error_type(msg)
        return False

    def raise_default_error(self):
        if not self.error_msg:
            raise self.error_type
        elif self.is_login_error or self.is_clearout_error:
            raise self.error_type(self.error_msg)
        else:
            msg = self.action + " failed\n" + self.error_msg
            raise self.error_type(msg)

    @classmethod
    def test_course_title(cls, html, course_id):
        href = '/product.html?sku=' + course_id
        title = html.find('a', {
            'href': href
        })
        if title is None:
            msg = cls.error_prefix + \
                "Authentication attempt failed\n" + \
                "Invalid course id: " + course_id
            raise AuthenticationError(msg)
        return title.contents[0]


class Session(object):

    errors_without_traceback = [
        AuthenticationError,
        HTMLError,
        DownloadError,
        RequestException,
        KeyboardInterrupt
    ]

    def __init__(self, session):
        self.session = session
        self.host = "https://learn.infiniteskills.com/"
        self.ajax_headers = self.get_ajax_headers()
        self.login_attempts = 0

    def __enter__(self):
        self.try_login()
        print("")
        return self

    def __exit__(self, type, value, traceback):
        if type in self.errors_without_traceback:
            if type is not KeyboardInterrupt:
                print(value, file=sys.stderr)
            print("")
            self.try_logout()
            sys.exit(1)
        self.try_logout()

    def force_exit(self, error, msg=None):
        if msg is not None:
            msg = ResponseParser.error_prefix + msg
            print(msg, file=sys.stderr)
        raise SystemExit(error)

    def try_login(self):
        print("Logging into account")
        try:
            self.login_attempts += 1
            self.startup()
            self.login()
        except (LoginError, RequestException) as e:
            msg = "Cannot log into account"
            self.force_exit(e, msg)
        except ClearoutError as e:
            msg = "Cannot clear out of all active sessions"
            self.force_exit(e, msg)
        except KeyboardInterrupt as e:
            self.force_exit(e)

    def try_logout(self):
        try:
            self.logout()
        except RequestException as e:
            msg = "Cannot log out of account"
            self.force_exit(e, msg)
        except KeyboardInterrupt:
            print("")

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

    def __init__(self, id, content):
        self.id = id
        self.html = BeautifulSoup(content, 'html.parser')
        self.title = self.get_title()
        self.resource_host = "http://bitcast-r.v1.iad1.bitgravity.com/"
        self.lectures = self.get_lectures()
        self.sections = self.get_sections()
        self.working_files_id = self.get_working_files_id()
        self.last_skipped = False
        print_msg("Checking into course", self.title)
        print("")

    def get_title(self):
        title = ResponseParser.test_course_title(self.html, self.id)
        return title

    @staticmethod
    def format_lecture(raw):
        lecture = re.sub(r'[\n\t]*(\w+): "', r'"\1": "', raw)
        lecture = lecture.replace('\\', '')
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
        msg = ResponseParser.error_prefix + \
            "Cannot find any lectures for this course"
        raw_playlist = self.html.find('script', text=re.compile('playlist: '))
        if raw_playlist is None:
            raise HTMLError(msg)
        raw_lectures = re.findall(r'{image:.*?}', raw_playlist.contents[0],
                                  re.DOTALL)
        if len(raw_lectures) == 0:
            raise HTMLError(msg)
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

    # output format: '?e=1672341893&h=8d8fba20cd6a39739114e23464be721&pos=0'
    def authenticate(self, lecture, session):
        url = session.host + "ajax/player.html"
        params = {key: lecture[key] for key in ['t', 'index', 'file', 'vid']}
        params['action'] = 'hash'
        if self.last_skipped:
            print("")
        self.last_skipped = False
        print_msg("Authenticating lecture", lecture['title'])
        auth_params = session.session.get(url,
                                          headers=session.ajax_headers,
                                          params=params)
        session.check_response(auth_params, AuthenticationError)
        if auth_params.text.startswith('<!DOCTYPE html>'):
            # try a second time
            auth_params = session.session.get(url,
                                              headers=session.ajax_headers,
                                              params=params)
            session.check_response(auth_params, AuthenticationError)
            if auth_params.text.startswith('<!DOCTYPE html>'):
                msg = ResponseParser.error_prefix + \
                    "No authentication params were returned"
                raise AuthenticationError(msg)
        return auth_params.text

    def make_filename(self, lecture):
        short_filename = lecture['file'].rsplit('/', 1)[-1]
        name, extension = os.path.splitext(short_filename)
        lecture_title = self.sanitize_filename(lecture['title'])
        filename = name + '. ' + lecture_title + extension
        title = self.sanitize_filename(self.title)
        section = self.sanitize_filename(lecture['section'])
        dirname = title + '/' + section + '/'
        return dirname + filename

    @staticmethod
    def stream(streaming_file, local_file):
        try:
            with open(local_file, 'wb') as f:
                for chunk in streaming_file.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
        except KeyboardInterrupt as e:
            with suppress(FileNotFoundError):
                print("")
                print_msg("Removing incomplete download file", local_file)
                os.remove(local_file)
            raise e
        except FileNotFoundError as e:
            error = ResponseParser.error_prefix + \
                re.sub(r'\[.+\] ', '', str(e))
            raise DownloadError(error)

    def download(self, lecture, session):
        local_file = self.make_filename(lecture)
        if os.path.isfile(local_file):
            print_msg("Skipping download of existing file", local_file)
            self.last_skipped = True
            return
        url = self.resource_host + "infiniteskills/"
        url += lecture['file'].split('/', 3)[3]
        auth_params = self.authenticate(lecture, session)
        url += auth_params
        print_msg("Downloading file", local_file, url=url)
        streaming_file = session.session.get(url, stream=True)
        session.check_response(streaming_file, DownloadError, stream=True)
        self.stream(streaming_file, local_file)
        print("")

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

    def authenticate_working_files(self, session):
        if self.test_working_files() is None:
            return
        wfid = self.working_files_id
        ajax_headers = session.ajax_headers
        url = session.host + "ajax/history.html"
        params = {
            'event': 'file',
            'id': wfid
        }
        print_msg("Authenticating course working files id", wfid)
        zip_url = session.session.get(url, params=params, headers=ajax_headers)
        session.check_response(zip_url, AuthenticationError)
        if zip_url.text.startswith('<!DOCTYPE html>'):
            msg = ResponseParser.error_prefix + "No zip file url was returned"
            raise AuthenticationError(msg)
        return zip_url.text

    def download_working_files(self, session):
        zip_url = self.authenticate_working_files(session)
        if zip_url is None:
            print("")
            return
        print_msg("Downloading course working files", url=zip_url.strip('\n'))
        zip_file = session.session.get(zip_url, stream=True)
        session.check_response(zip_file, DownloadError, stream=True)
        with ZipFile(io.BytesIO(zip_file.content)) as myzip:
            myzip.extractall(self.title)
        print("")


if __name__ == "__main__":
    course_ids = sys.argv[1:]
    if len(course_ids) == 0:
        msg = ResponseParser.error_prefix + \
            "Please provide at least one course id as argument"
        raise SystemExit(msg)
    with requests.Session() as s, Session(s) as session:
        for course_id in course_ids:
            course_content = session.authenticate(course_id).content
            course = Course(course_id, course_content)
            course.makedirs()
            course.download_working_files(session)
            for lecture in course.lectures:
                course.download(lecture, session)
            if course.last_skipped:
                print("")
            print_msg("Done with course " + course_id, course.title)
            print("")
