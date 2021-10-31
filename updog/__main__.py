import os
import signal
import argparse

from flask import Flask, render_template, send_file, redirect, request, send_from_directory, url_for, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.serving import run_simple

from updog.utils.path import is_valid_subpath, is_valid_upload_path, get_parent_directory, process_files
from updog.utils.output import error, info, warn, success
from updog import version as VERSION


def read_write_directory(directory):
    if os.path.exists(directory):
        if os.access(directory, os.W_OK and os.R_OK):
            return directory
        else:
            error('The output is not readable and/or writable')
    else:
        error('The specified directory does not exist')


def parse_arguments():
    parser = argparse.ArgumentParser(prog='updog')
    cwd = os.getcwd()
    parser.add_argument('-d', '--directory', metavar='DIRECTORY', type=read_write_directory, default=cwd,
                        help='Root directory\n'
                             '[Default=.]')
    parser.add_argument('-p', '--port', type=int, default=9090,
                        help='Port to serve [Default=9090]')
    parser.add_argument('--password', type=str, default='', help='Require basic authentication with this password to access the page. (no authentication by default)')
    parser.add_argument('--username', type=str, default='', help='Set the username for basic authentication. (Default=\'\')')
    parser.add_argument('--allow-download', default=False, help='Allows download of files without authentication.', action='store_const', const=True)
    parser.add_argument('--ssl', action='store_true', help='Use an encrypted connection')
    parser.add_argument('--version', action='version', version='%(prog)s v'+VERSION)

    args = parser.parse_args()

    # Normalize the path
    args.directory = os.path.abspath(args.directory)

    return args


def main():
    args = parse_arguments()

    app = Flask(__name__)
    global auth
    auth = HTTPBasicAuth()

    global base_directory
    base_directory = args.directory

    # Deal with Favicon requests
    # Require authentication if password is set to prevent spiders from detecting updog by the favicon
    @app.route('/favicon.ico')
    @auth.login_required
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'static'),
                                   'images/favicon.ico', mimetype='image/vnd.microsoft.icon')

    ############################################
    # File Browsing and Download Functionality #
    ############################################
    @app.route('/', defaults={'path': None})
    @app.route('/<path:path>')
    @auth.login_required(optional=args.allow_download)
    def home(path):
        # If there is a path parameter and it is valid
        if path and is_valid_subpath(path, base_directory):

            # Check if authenticated or resource may be accessed without authentication 
            if args.password != '' and auth.current_user() is False and args.allow_download is False:
                return auth.auth_error_callback(401)

            # Take off the trailing '/'
            path = os.path.normpath(path)
            requested_path = os.path.join(base_directory, path)

            # If directory
            if os.path.isdir(requested_path):
                back = get_parent_directory(requested_path, base_directory)
                is_subdirectory = True

            # If file
            elif os.path.isfile(requested_path):

                # Check if the view flag is set
                if request.args.get('view') is None:
                    send_as_attachment = True
                else:
                    send_as_attachment = False

                # Check if file extension
                (filename, extension) = os.path.splitext(requested_path)
                if extension == '':
                    mimetype = 'text/plain'
                else:
                    mimetype = None

                try:
                    return send_file(requested_path, mimetype=mimetype, as_attachment=send_as_attachment)
                except PermissionError:
                    abort(403, 'Read Permission Denied: ' + requested_path)

        else:
            # Root home configuration
            is_subdirectory = False
            path = ''
            requested_path = base_directory
            back = ''

        # Check if authenticated or no authentication requuired
        if args.password != '' and auth.current_user() is False:
                return auth.auth_error_callback(401)
        
        if os.path.exists(requested_path):
            # Read the files
            try:
                directory_files = process_files(os.scandir(requested_path), base_directory)
            except PermissionError:
                abort(403, 'Read Permission Denied: ' + path)

            return render_template('home.html', files=directory_files, back=back,
                                   directory=path, is_subdirectory=is_subdirectory, version=VERSION)
        else:
            return redirect('/')


    ##################################
    # REST File Upload Functionality #
    ##################################
    @app.route('/<path:path>', methods=['POST'])
    @auth.login_required
    def rest_upload(path):
        target_directory = os.path.abspath(os.path.join(base_directory, os.path.dirname(path)))
        target_file = os.path.basename(path)
        if not (os.path.isdir(target_directory) and is_valid_subpath(path, base_directory)):
            abort(404, 'Invalid Path: ' + path)
        files = request.files.getlist("file")
        if len(files) > 0 and len(target_file) == 0:
            # path is targeting a directory
            # content is multipart/form-data, take the uploaded files 
            for f in files:
                target = os.path.join(target_directory, secure_filename(f.filename))    
                try:
                    f.save(target)
                except PermissionError:
                    abort(403, 'Write Permission Denied: ' + path)
        elif len(files) > 0 and len(target_file) > 0:
            # path is targeting a file
            # content is multipart/form-data, take the first uploaded file
            target = os.path.join(target_directory, target_file)
            try:
                files[0].save(target)
            except PermissionError:
                abort(403, 'Write Permission Denied: ' + path)
        else:
            # take the raw request body as content 
            if len(target_file) == 0:
                # fail if the path is not a file
                abort(404, 'Invalid Filename: ' + target_file)
            target = os.path.join(target_directory, target_file)
            try:
                with open(target, "wb") as f:
                    f.write(request.data) 
            except PermissionError:
                abort(403, 'Write Permission Denied: ' + path)
        # do not return anything
        return ('', 204)


    ##################################
    # Form File Upload Functionality #
    ##################################
    @app.route('/upload', methods=['POST'])
    @auth.login_required
    def upload():
        if request.method == 'POST':

            # No file part - needs to check before accessing the files['file']
            if 'file' not in request.files:
                return redirect(request.referrer)

            path = request.form['path']
            # Prevent file upload to paths outside of base directory
            if not is_valid_upload_path(path, base_directory):
                return redirect(request.referrer)

            for file in request.files.getlist('file'):

                # No filename attached
                if file.filename == '':
                    return redirect(request.referrer)

                # Assuming all is good, process and save out the file
                if file:
                    filename = secure_filename(file.filename)
                    full_path = os.path.join(base_directory, os.path.normpath(path), filename)
                    try:
                        file.save(full_path)
                    except PermissionError:
                        abort(403, 'Write Permission Denied: ' + path)

            return redirect(request.referrer)

    # Password functionality is without username
    users = {
        args.username: generate_password_hash(args.password)
    }

    @auth.verify_password
    def verify_password(username, password):
        if args.password:
            if username in users:
                return check_password_hash(users.get(username), password)
            return False
        else:
            return True

    # Inform user before server goes up
    success('Serving {}...'.format(args.directory, args.port))

    def handler(signal, frame):
        print()
        error('Exiting!')
    signal.signal(signal.SIGINT, handler)

    ssl_context = None
    if args.ssl:
        ssl_context = 'adhoc'

    run_simple("0.0.0.0", int(args.port), app, ssl_context=ssl_context)


if __name__ == '__main__':
    main()
