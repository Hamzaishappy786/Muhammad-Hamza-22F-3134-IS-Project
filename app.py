from flask import Flask, request, render_template, jsonify, send_file
from tensorflow.keras.models import load_model
from PIL import Image
import numpy as np
import os
import re
import csv
import io
import uuid
import threading
from datetime import datetime

app = Flask(__name__)
model = load_model('./modelFinal/best_model.keras')

image_size = 32
MAX_MATCH_RESULTS = 200
VIRUS_LIST_PATH = os.path.join(app.root_path, 'dataset', 'viruses.txt')
DEFAULT_SCAN_EXTENSIONS = {'.exe', '.dll', '.sys', '.vbs', '.scr', '.pif', '.dat', '.com', '.tmp'}
scan_jobs = {}
scan_jobs_lock = threading.Lock()

def preprocess_input(image):
    image = image.resize((image_size, image_size))
    image = image.convert('L')
    image_array = np.array(image)
    normalized_image = image_array / 255.0
    reshaped_image = normalized_image.reshape(1, image_size, image_size, 1)
    return reshaped_image


def load_virus_signatures():
    signatures = set()
    filename_pattern = re.compile(r'([A-Za-z0-9_.~\-]+\.(?:exe|dll|sys|vbs|scr|pif|dat|com|tmp))', re.IGNORECASE)

    with open(VIRUS_LIST_PATH, 'r', encoding='utf-8') as virus_file:
        for raw_line in virus_file:
            line = raw_line.strip()
            if not line:
                continue

            primary_name = line.split('(')[0].strip()
            if primary_name:
                signatures.add(primary_name.lower())

            for matched_name in filename_pattern.findall(line):
                signatures.add(matched_name.lower())

    return signatures


def available_system_roots():
    if os.name == 'nt':
        drives = []
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f'{letter}:\\'
            if os.path.exists(drive):
                drives.append(drive)
        return drives
    return ['/']


def normalize_scan_roots(scan_mode, target_path):
    if scan_mode == 'system':
        roots = available_system_roots()
        if not roots:
            raise ValueError('No accessible drives were found for a full system scan.')
        return roots

    if not target_path:
        raise ValueError('Please provide a target path for drive/folder scan.')

    normalized_path = os.path.abspath(target_path)

    if scan_mode == 'drive':
        if os.name == 'nt':
            drive_root = os.path.splitdrive(normalized_path)[0]
            if not drive_root:
                raise ValueError('Enter a valid drive path like C:\\')
            normalized_path = f'{drive_root}\\'

        if not os.path.exists(normalized_path):
            raise ValueError('The selected drive was not found.')
        return [normalized_path]

    if scan_mode == 'folder':
        if not os.path.isdir(normalized_path):
            raise ValueError('The selected folder does not exist.')
        return [normalized_path]

    raise ValueError('Invalid scan mode selected.')


def normalize_extensions(extensions_text):
    if not extensions_text:
        return DEFAULT_SCAN_EXTENSIONS

    extensions = set()
    for item in extensions_text.split(','):
        ext = item.strip().lower()
        if not ext:
            continue
        if not ext.startswith('.'):
            ext = f'.{ext}'
        if not re.fullmatch(r'\.[a-z0-9]{1,10}', ext):
            raise ValueError(f'Invalid extension format: {item.strip()}')
        extensions.add(ext)

    if not extensions:
        raise ValueError('Please enter at least one extension.')
    return extensions


def search_virus_filenames(scan_mode, target_path, virus_signatures, allowed_extensions=None, progress_callback=None):
    roots = normalize_scan_roots(scan_mode, target_path)
    extension_filter = {ext.lower() for ext in (allowed_extensions or DEFAULT_SCAN_EXTENSIONS)}

    matches = []
    scanned_files = 0
    truncated = False
    skipped_by_extension = 0

    for root in roots:
        for current_root, _, files in os.walk(root, topdown=True, onerror=lambda _: None):
            for filename in files:
                scanned_files += 1
                extension = os.path.splitext(filename)[1].lower()
                if extension_filter and extension not in extension_filter:
                    skipped_by_extension += 1
                    if progress_callback and scanned_files % 500 == 0:
                        progress_callback(scanned_files, matches, False, skipped_by_extension)
                    continue

                if filename.lower() in virus_signatures:
                    matches.append(os.path.join(current_root, filename))
                    if len(matches) >= MAX_MATCH_RESULTS:
                        truncated = True
                        if progress_callback:
                            progress_callback(scanned_files, matches, True, skipped_by_extension)
                        return matches, scanned_files, roots, truncated, skipped_by_extension

                if progress_callback and scanned_files % 500 == 0:
                    progress_callback(scanned_files, matches, False, skipped_by_extension)

    if progress_callback:
        progress_callback(scanned_files, matches, True, skipped_by_extension)
    return matches, scanned_files, roots, truncated, skipped_by_extension


def create_scan_job(scan_mode, scan_target, allowed_extensions):
    job_id = uuid.uuid4().hex
    job_data = {
        'job_id': job_id,
        'status': 'running',
        'created_at': datetime.utcnow().isoformat(),
        'scan_mode': scan_mode,
        'scan_target': scan_target,
        'extensions': sorted(allowed_extensions),
        'checked_files': 0,
        'skipped_by_extension': 0,
        'matches': [],
        'roots': [],
        'truncated': False,
        'error': None
    }
    with scan_jobs_lock:
        scan_jobs[job_id] = job_data

    thread = threading.Thread(
        target=run_scan_job,
        args=(job_id, scan_mode, scan_target, allowed_extensions),
        daemon=True
    )
    thread.start()
    return job_id


def run_scan_job(job_id, scan_mode, scan_target, allowed_extensions):
    def update_progress(scanned_files, matches, is_final, skipped_by_extension):
        with scan_jobs_lock:
            job = scan_jobs.get(job_id)
            if not job:
                return
            job['checked_files'] = scanned_files
            job['matches'] = matches[:]
            job['skipped_by_extension'] = skipped_by_extension
            if is_final:
                job['status'] = 'completed'

    try:
        target_value = '' if scan_mode == 'system' else scan_target
        matches, scanned_files, roots, truncated, skipped_by_extension = search_virus_filenames(
            scan_mode,
            target_value,
            virus_signatures,
            allowed_extensions=allowed_extensions,
            progress_callback=update_progress
        )
        with scan_jobs_lock:
            job = scan_jobs.get(job_id)
            if not job:
                return
            job['matches'] = matches
            job['checked_files'] = scanned_files
            job['roots'] = roots
            job['truncated'] = truncated
            job['skipped_by_extension'] = skipped_by_extension
            job['status'] = 'completed'
    except ValueError as exc:
        with scan_jobs_lock:
            job = scan_jobs.get(job_id)
            if job:
                job['status'] = 'failed'
                job['error'] = str(exc)
    except Exception:
        with scan_jobs_lock:
            job = scan_jobs.get(job_id)
            if job:
                job['status'] = 'failed'
                job['error'] = 'Unexpected scan error occurred.'


virus_signatures = load_virus_signatures()

@app.route('/', methods=['GET', 'POST'])
def index():
    context = {
        'result': None,
        'probability': None,
        'scan_error': None,
        'scan_mode': 'system',
        'scan_target': '',
        'scan_matches': [],
        'scan_checked_files': 0,
        'scan_skipped_by_extension': 0,
        'scan_roots': [],
        'scan_truncated': False,
        'scan_extensions': ', '.join(sorted(DEFAULT_SCAN_EXTENSIONS)),
        'scan_job_id': None,
        'scan_status': None,
        'available_drives': available_system_roots() if os.name == 'nt' else []
    }

    job_id = request.args.get('job_id', '').strip()
    if job_id:
        with scan_jobs_lock:
            existing_job = scan_jobs.get(job_id)
        if existing_job:
            context['scan_job_id'] = existing_job['job_id']
            context['scan_status'] = existing_job['status']
            context['scan_mode'] = existing_job['scan_mode']
            context['scan_target'] = existing_job['scan_target']
            context['scan_extensions'] = ', '.join(existing_job['extensions'])
            context['scan_matches'] = existing_job['matches']
            context['scan_checked_files'] = existing_job['checked_files']
            context['scan_skipped_by_extension'] = existing_job['skipped_by_extension']
            context['scan_roots'] = existing_job['roots']
            context['scan_truncated'] = existing_job['truncated']
            context['scan_error'] = existing_job['error']

    if request.method == 'POST':
        form_type = request.form.get('form_type', 'image_scan')

        if form_type == 'image_scan':
            file = request.files.get('file')
            if file:
                image = Image.open(file.stream)
                input_data = preprocess_input(image)
                prediction = model.predict(input_data)[0][0]
                context['result'] = 'Malware' if prediction >= 0.5 else 'Benign'
                context['probability'] = prediction if prediction >= 0.5 else 1 - prediction
            return render_template('index.html', **context)

        if form_type == 'file_scan':
            context['scan_mode'] = request.form.get('scan_mode', 'system')
            context['scan_target'] = request.form.get('scan_target', '').strip()
            context['scan_extensions'] = request.form.get('scan_extensions', '').strip()

            try:
                allowed_extensions = normalize_extensions(context['scan_extensions'])
                job_id = create_scan_job(context['scan_mode'], context['scan_target'], allowed_extensions)
                context['scan_job_id'] = job_id
                context['scan_status'] = 'running'
                context['scan_extensions'] = ', '.join(sorted(allowed_extensions))
            except ValueError as exc:
                context['scan_error'] = str(exc)

            return render_template('index.html', **context)

    return render_template('index.html', **context)


@app.route('/scan-status/<job_id>', methods=['GET'])
def scan_status(job_id):
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify({
            'job_id': job['job_id'],
            'status': job['status'],
            'checked_files': job['checked_files'],
            'skipped_by_extension': job['skipped_by_extension'],
            'matches': job['matches'],
            'roots': job['roots'],
            'truncated': job['truncated'],
            'error': job['error'],
            'extensions': job['extensions']
        })


@app.route('/scan-export/<job_id>/<fmt>', methods=['GET'])
def export_scan(job_id, fmt):
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

    if not job:
        return 'Scan job not found.', 404
    if job['status'] != 'completed':
        return 'Scan is not completed yet.', 400

    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    if fmt == 'txt':
        txt_buffer = io.StringIO()
        txt_buffer.write('Malware File Name Scan Report\n')
        txt_buffer.write(f'Generated at (UTC): {timestamp}\n')
        txt_buffer.write(f'Scan mode: {job["scan_mode"]}\n')
        txt_buffer.write(f'Scan target: {job["scan_target"] or "full system"}\n')
        txt_buffer.write(f'Extensions: {", ".join(job["extensions"])}\n')
        txt_buffer.write(f'Checked files: {job["checked_files"]}\n')
        txt_buffer.write(f'Skipped by extension filter: {job["skipped_by_extension"]}\n')
        txt_buffer.write(f'Matches found: {len(job["matches"])}\n\n')
        for path in job['matches']:
            txt_buffer.write(f'{path}\n')

        data = io.BytesIO(txt_buffer.getvalue().encode('utf-8'))
        return send_file(data, as_attachment=True, download_name=f'scan_report_{timestamp}.txt', mimetype='text/plain')

    if fmt == 'csv':
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(['path'])
        for path in job['matches']:
            writer.writerow([path])

        data = io.BytesIO(csv_buffer.getvalue().encode('utf-8'))
        return send_file(data, as_attachment=True, download_name=f'scan_report_{timestamp}.csv', mimetype='text/csv')

    return 'Unsupported export format.', 400

if __name__ == '__main__':
    app.run(debug=True)
