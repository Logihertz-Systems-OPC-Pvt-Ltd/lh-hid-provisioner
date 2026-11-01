# ==============================================================================
# Product:       lh-hid-provisioner (lh-provision)
# Module:        tests.test_templates
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for declarative YAML profile templates."""

import pytest

from lh_hid_provisioner.compiler import compile_profile
from lh_hid_provisioner.linter import lint_script
from lh_hid_provisioner.models import TargetOS
from lh_hid_provisioner.parser import parse_profile
from lh_hid_provisioner.templates import generate_template


@pytest.mark.parametrize("target_os", [TargetOS.DEBIAN, TargetOS.UBUNTU, TargetOS.ALPINE])
def test_templates_validity_and_compilation(target_os: TargetOS) -> None:
    template_yaml = generate_template(target_os)
    assert (
        f"Target OS: {target_os.value}" in template_yaml or target_os.value in template_yaml.lower()
    )

    # 1. Parse template YAML
    profile = parse_profile(template_yaml)
    assert profile.version == "1"
    assert profile.networking.interface != ""
    assert len(profile.ssh.authorized_keys) > 0

    # 2. Compile to HID script
    hid_script = compile_profile(profile, target_os)
    assert f"Target OS: {target_os.value}" in hid_script

    # 3. Lint compiled script to ensure 100% compliance
    report = lint_script(hid_script)
    assert report.total_issues == 0
