import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DebianPackagingTests(unittest.TestCase):
    def test_postinst_does_not_contact_sensor_or_modify_auth_stack(self):
        postinst = (ROOT / 'debian/python3-validity.postinst').read_text()

        self.assertNotIn('udevadm trigger', postinst)
        self.assertNotIn('pam-auth-update', postinst)
        self.assertIn('udevadm control --reload-rules', postinst)

    def test_dpkg_does_not_start_driver_mid_transaction(self):
        rules = (ROOT / 'debian/rules').read_text()

        self.assertIn(
            'dh_installsystemd --name=python3-validity --no-start',
            rules,
        )

    def test_matched_hardware_still_starts_without_manual_configuration(self):
        rules = (ROOT / 'debian/python3-validity.udev').read_text()

        self.assertIn('ACTION=="add|change"', rules)
        self.assertIn('start python3-validity.service', rules)
        self.assertIn('LABEL="python_validity_match"', rules)

    def test_unit_execstart_is_shipped_as_a_data_file(self):
        setup_py = (ROOT / 'setup.py').read_text()
        unit = (ROOT / 'debian/python3-validity.service').read_text()

        self.assertIn(
            "('lib/python-validity/', ['dbus_service/dbus-service'])",
            setup_py,
        )
        self.assertIn('ExecStart=/usr/lib/python-validity/dbus-service', unit)

    def test_installer_uses_the_debian_layout_not_easy_install(self):
        script = (ROOT / 'install-00bb.sh').read_text()

        # Plain `setup.py install` can fall back to easy_install, which
        # silently skips data_files: no dbus-service, so the unit died with
        # status=203/EXEC while the script still reported success.
        self.assertIn('--single-version-externally-managed', script)
        self.assertIn('--install-layout=deb', script)
        self.assertIn('lib/python-validity/dbus-service', script)


if __name__ == '__main__':
    unittest.main()
