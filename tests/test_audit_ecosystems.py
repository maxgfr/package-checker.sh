"""Audit regressions in Maven, file discovery, remediation and runtime detection."""
import json

from test_audit import AuditCase


class MavenTests(AuditCase):
    def test_project_properties_win_over_profile_properties(self):
        pom = """<project>
  <profiles><profile><id>p</id><properties><demo.version>9.9.9</demo.version></properties></profile></profiles>
  <properties><demo.version>1.5.0</demo.version><other.version>2.0</other.version></properties>
  <dependencies>
    <!-- <dependency><groupId>x</groupId><artifactId>commented</artifactId><version>1.0</version></dependency> -->
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo</artifactId>
      <version>${demo.version}</version>
      <exclusions><exclusion><groupId>org.wrong</groupId><artifactId>wrong</artifactId><version>1.0</version></exclusion></exclusions>
    </dependency>
    <dependency><groupId>org.example</groupId><artifactId>other</artifactId><version>
        ${other.version}
    </version></dependency>
  </dependencies>
</project>
"""
        self.assertEqual(self.findings("pom.xml", pom, "pkg:maven/org.example/demo@1.5.0",
                                       "pkg:maven/org.example/demo@9.9.9", "pkg:maven/org.example/other@2.0",
                                       "pkg:maven/x/commented@1.0", "pkg:maven/org.wrong/wrong@1.0"),
                         {"org.example:demo@1.5.0", "org.example:other@2.0"})

    def test_profile_only_property_still_resolves(self):
        pom = ("<project><profiles><profile><properties><v>1.5.0</v></properties></profile></profiles>"
               "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version>"
               "</dependency></dependencies></project>")
        self.assertEqual(self.findings("pom.xml", pom, "pkg:maven/g/a@1.5.0"), {"g:a@1.5.0"})


class DiscoveryTests(AuditCase):
    def test_common_requirement_and_gradle_lockfile_names(self):
        self.write("dev-requirements.txt", "devonly==1.0.0\n")
        self.write("requirements_test.txt", "testonly==1.0.0\n")
        self.write("constraints.txt", "pinned==1.0.0\n")
        self.write("buildscript-gradle.lockfile", "org.example:plugin:1.5.0=classpath\nempty=\n")
        found = self.findings("requirements.txt", "base==1.0.0\n", "pkg:pypi/devonly@1.0.0", "pkg:pypi/testonly@1.0.0",
                              "pkg:pypi/pinned@1.0.0", "pkg:pypi/base@1.0.0", "pkg:maven/org.example/plugin@1.5.0")
        self.assertEqual(found, {"devonly@1.0.0", "testonly@1.0.0", "pinned@1.0.0", "base@1.0.0",
                                 "org.example:plugin@1.5.0"})


class RemediationTests(AuditCase):
    def test_swift_update_uses_the_package_identity(self):
        output = self.shell('fix_commands_for_eco swift github.com/apple/swift-nio ""')
        self.assertIn("swift package update swift-nio", output)


class RuntimeDetectionTests(AuditCase):
    def test_runtime_versions_are_read_from_top_level_members_only(self):
        self.write("package.json", json.dumps({"keywords": ["engines"], "config": {"engines": {"node": "1.0.0"}},
                                               "engines": {"node": "22.1.0"}, "volta": {"node": "20.0.0"}}))
        self.write("composer.json", json.dumps({"require": {"php": "^8.1"}, "config": {"platform": {"php": "8.3.10"}},
                                                "description": "php"}))
        output = self.shell("runtime_specs package.json; runtime_specs composer.json")
        self.assertEqual(output.splitlines(), ["node|22.1.0", "node|20.0.0", "php|8.3.10", "php|^8.1"])
