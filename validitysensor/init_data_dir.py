import os
import shutil

PYTHON_VALIDITY_DATA_DIR = '/var/run/python-validity/'
PYTHON_VALIDITY_STATE_DIR = '/var/lib/python-validity/'


def migrate_legacy_calibration(runtime_dir=PYTHON_VALIDITY_DATA_DIR,
                               state_dir=PYTHON_VALIDITY_STATE_DIR):
    legacy_path = os.path.join(runtime_dir, 'calib-data.bin')
    state_path = os.path.join(state_dir, 'calib-data.bin')
    if os.path.isfile(legacy_path) and not os.path.exists(state_path):
        temporary_path = state_path + '.migrating'
        shutil.copyfile(legacy_path, temporary_path)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, state_path)


def init_data_dir():
    for path in (PYTHON_VALIDITY_DATA_DIR, PYTHON_VALIDITY_STATE_DIR):
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    migrate_legacy_calibration()
