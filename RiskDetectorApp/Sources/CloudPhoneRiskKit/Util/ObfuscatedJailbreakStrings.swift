import Foundation

extension ObfuscatedConstants {

    static var jailbreakSuspiciousPaths: [(path: String, score: Double)] {
        [
            (b64("L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA="), 30),
            (b64("L0FwcGxpY2F0aW9ucy9TaWxlby5hcHA="), 30),
            (b64("L0FwcGxpY2F0aW9ucy9aZWJyYS5hcHA="), 25),
            (b64("L0FwcGxpY2F0aW9ucy9JbnN0YWxsZXIuYXBw"), 20),
            (b64("L0FwcGxpY2F0aW9ucy9GaWx6YS5hcHA="), 20),
            (b64("L0FwcGxpY2F0aW9ucy9pRmlsZS5hcHA="), 15),
            (b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRlL01vYmlsZVN1YnN0cmF0ZS5keWxpYg=="), 25),
            (b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRlL0R5bmFtaWNMaWJyYXJpZXM="), 20),
            (b64("L1VzZXIvTGlicmFyeS9GcmFtZXdvcmtzL0N5ZGlhU3Vic3RyYXRlLmZyYW1ld29yaw=="), 25),
            (b64("L3Vzci9saWIvbGlic3Vic3RyYXRlLmR5bGli"), 20),
            (b64("L3Vzci9saWIvbGlic3Vic3RpdHV0ZS5keWxpYg=="), 20),
            (b64("L3Vzci9saWIvc3Vic3RpdHV0ZQ=="), 25),
            (b64("L3Vzci9saWIvRWxsZUtpdC5keWxpYg=="), 25),
            (b64("L3Vzci9saWIvbGlib29rZXIuZHlsaWI="), 20),
            (b64("L3Zhci9qYg=="), 15),
            (b64("L3Zhci9qYi91c3IvYmluL3NzaA=="), 10),
            (b64("L3Zhci9qYi9BcHBsaWNhdGlvbnMvU2lsZW8uYXBw"), 20),
            (b64("L3Zhci9qYi9MaWJyYXJ5L01vYmlsZVN1YnN0cmF0ZS9Nb2JpbGVTdWJzdHJhdGUuZHlsaWI="), 25),
            (b64("L3Zhci9qYi91c3IvbGliL0VsbGVLaXQuZHlsaWI="), 25),
            (b64("L0FwcGxpY2F0aW9ucy9jaGVja3JhMW4uYXBw"), 25),
            (b64("L0FwcGxpY2F0aW9ucy9vZHlzc2V5LmFwcA=="), 20),
            (b64("L0FwcGxpY2F0aW9ucy91bmMwdmVyLmFwcA=="), 25),
            (b64("L0FwcGxpY2F0aW9ucy9UYXVyaW5lLmFwcA=="), 20),
            (b64("L2V0Yy9hcHQ="), 25),
            (b64("L2V0Yy9hcHQvc291cmNlcy5saXN0"), 20),
            (b64("L2V0Yy9hcHQvc291cmNlcy5saXN0LmQ="), 20),
            (b64("L3Zhci9saWIvYXB0"), 15),
            (b64("L3Vzci9zYmluL3NzaGQ="), 15),
            (b64("L3Vzci9iaW4vc3No"), 10),
            (b64("L2Jpbi9iYXNo"), 10),
        ]
    }

    static var jailbreakCriticalPaths: [String] {
        [
            b64("L2V0Yy9hcHQ="),
            b64("L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA="),
            b64("L3Zhci9qYg=="),
            b64("L3Vzci9saWIvRWxsZUtpdC5keWxpYg=="),
            b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRlL01vYmlsZVN1YnN0cmF0ZS5keWxpYg=="),
        ]
    }

    /// 噪声路径：正常系统路径，用于在检查越狱路径前插入 stat 调用，干扰 Stalker 区分检测目标
    static var pathNoisePaths: [String] {
        [
            b64("L3Vzci9saWIvZHlsZA=="),           // /usr/lib/dyld
            b64("L2V0Yy9wYXNzd2Q="),               // /etc/passwd
            b64("L2Rldi9udWxs"),                   // /dev/null
            b64("L3Vzci9saWIvbGliU3lzdGVtLkIuZHlsaWI="),  // /usr/lib/libSystem.B.dylib
            b64("L1N5c3RlbS9MaWJyYXJ5L0NvcmVTZXJ2aWNlcy9TeXN0ZW1WZXJzaW9uLnBsaXN0"),  // SystemVersion.plist
        ]
    }

    static var sysctlSuspiciousProcessNeedles: [String] {
        [
            b64("Y3lkaWE="),
            b64("c2lsZW8="),
            b64("ZmlsemE="),
            b64("c3NoZA=="),
            b64("ZHJvcGJlYXI="),
            b64("ZnJpZGE="),
            b64("ZGVidWdzZXJ2ZXI="),
            b64("Y3ljcmlwdA=="),
            b64("c3Vic3RyYXRlZA=="),
            b64("c3Vic3RpdHV0ZQ=="),
            b64("ZWxsZWtpdA=="),
            b64("YXB0"),
            b64("ZHBrZw=="),
        ]
    }

    static var sysctlSuspiciousParentNeedles: [String] {
        [
            b64("Y3lkaWE="),
            b64("c2lsZW8="),
            b64("ZmlsemE="),
            b64("ZnJpZGE="),
            b64("ZGVidWdzZXJ2ZXI="),
            b64("bGxkYg=="),
            b64("Z2Ri"),
        ]
    }

    static var listApplicationsNeedles: [String] {
        [
            b64("c2lsZW8="),
            b64("Y3lkaWE="),
            b64("emVicmE="),
            b64("ZmlsemE="),
            b64("Y2hlY2tyYTFu"),
            b64("dGF1cmluZQ=="),
            b64("dW5jMHZlcg=="),
            b64("Y2hpbWVyYQ=="),
        ]
    }

    static var envSuspiciousVars: [(name: String, score: Double)] {
        [
            (b64("RFlMRF9JTlNFUlRfTElCUkFSSUVT"), 50),
            (b64("RFlMRF9MSUJSQVJZX1BBVEg="), 25),
            (b64("RFlMRF9GQUxMQkFDS19MSUJSQVJZX1BBVEg="), 20),
            (b64("RFlMRF9QUklOVF9MSUJSQVJJRVM="), 15),
            (b64("RFlMRF9QUklOVF9TRUdNRU5UUw=="), 12),
            (b64("RFlMRF9QUklOVF9JTklUSUFMSVpFUlM="), 12),
            (b64("RFlMRF9QUklOVF9ET0ZT"), 10),
            (b64("RFlMRF9QUklOVF9BUElT"), 10),
            (b64("RFlMRF9QUklOVF9TVEFUSVNUSUNT"), 10),
            (b64("RFlMRF9QUklOVF9XQVJOSU5HUw=="), 10),
            (b64("RFlMRF9WRVJCT1NF"), 10),
            (b64("RFlMRF9CSU5EX0FUX0xBVU5DSA=="), 10),
            (b64("TExEX0xJQlJBUllfUEFUSA=="), 20),
            (b64("TExEX1BSRU9BRQ=="), 25),
            (b64("RFlMRF9OT19QSUU="), 12),
            (b64("RFlMRF9ESVNBQkxFX1BSRUZFVENI"), 10),
        ]
    }

    static var systemConfigPaths: [String] {
        [
            b64("L2V0Yy9mc3RhYg=="),
            b64("L2V0Yy9ob3N0cw=="),
            b64("L2V0Yy9hcHQvc291cmNlcy5saXN0"),
            b64("L3ByaXZhdGUvZXRjL2ZzdGFi"),
            b64("L3ByaXZhdGUvZXRjL2hvc3Rz"),
        ]
    }

    static var hostsPath: String { b64("L2V0Yy9ob3N0cw==") }

    static var aptPaths: [String] {
        [
            b64("L2V0Yy9hcHQ="),
            b64("L2V0Yy9hcHQvc291cmNlcy5saXN0"),
            b64("L2V0Yy9hcHQvc291cmNlcy5saXN0LmQ="),
            b64("L3Zhci9saWIvYXB0"),
            b64("L3Zhci9jYWNoZS9hcHQ="),
            b64("L1VzZXIvTGlicmFyeS9hcHQ="),
        ]
    }

    static var aptSourcesListPath: String { b64("L2V0Yy9hcHQvc291cmNlcy5saXN0") }

    static var aptRepoNeedles: [String] {
        [b64("Y3lkaWE="), b64("YmlnYm9zcw=="), b64("bW9kbXlp")]
    }

    static var fstabPath: String { b64("L2V0Yy9mc3RhYg==") }

    static var suspiciousHostsEntries: [String] {
        [
            b64("MTI3LjAuMC4xIG9jc3A="),
            b64("MTI3LjAuMC4xIG9jc3Ay"),
            b64("MTI3LjAuMC4xICouYXBwbGUuY29t"),
            b64("YWRiY29ubmVjdA=="),
            b64("Y3lkaWE="),
            b64("c2lsZW8="),
        ]
    }

    static var suspiciousFstabMounts: [String] {
        [
            b64("L3Zhcg=="),
            b64("L0FwcGxpY2F0aW9ucy8="),
            b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRl"),
            b64("cnc="),
            b64("bm9kZXY="),
        ]
    }

    private static func b64(_ s: String) -> String {
        StringDeobfuscator.base64Decode(s)
    }
}
