Pod::Spec.new do |s|
  s.name             = 'CloudPhoneRiskKit'
  s.version          = '7.3.0'
  s.summary          = 'iOS 端环境风险检测 SDK — 识别越狱、云手机、Hook 注入与机房设备'
  s.description      = <<-DESC
    CloudPhoneRiskKit 是面向业务风控场景的本地信号采集与决策引擎 SDK。
    提供硬件指纹、行为熵分析、反篡改对抗与场景化策略，帮助 App 在端侧
    完成高质量的环境风险判定。支持越狱检测、Hook/注入检测、云手机识别、
    行为信号分析、设备一致性校验与服务端聚合信号融合。
  DESC

  s.homepage         = 'https://github.com/anthropic/cloudphone-risk-detector'
  s.license          = { :type => 'Proprietary', :text => 'Copyright (c) 2024-2026. All rights reserved.' }
  s.author           = { 'CloudPhoneRiskKit Team' => 'riskkit@example.com' }
  s.source           = {
    :git => 'https://github.com/anthropic/cloudphone-risk-detector.git',
    :tag => s.version.to_s
  }

  s.ios.deployment_target = '14.0'
  s.swift_version         = '5.9'

  s.requires_arc = true
  s.static_framework = true

  s.frameworks = 'Foundation', 'Security', 'CryptoKit'
  s.weak_frameworks = 'UIKit', 'CoreMotion', 'DeviceCheck', 'LocalAuthentication'

  s.pod_target_xcconfig = {
    'SWIFT_EMIT_MODULE_INTERFACE' => 'YES',
    'BUILD_LIBRARY_FOR_DISTRIBUTION' => 'YES',
    'OTHER_SWIFT_FLAGS' => '-DCOCOAPODS',
    'GCC_PREPROCESSOR_DEFINITIONS' => '$(inherited) COCOAPODS=1',
  }

  # ──────────────────────────────────────────────
  # Subspec: Core（最小集，不含 CRiskCore C 层加固）
  # ──────────────────────────────────────────────
  s.subspec 'Core' do |core|
    core.source_files = [
      'RiskDetectorApp/Sources/CloudPhoneRiskKit/**/*.swift',
    ]
    core.exclude_files = [
      'RiskDetectorApp/Sources/CloudPhoneRiskKit/Internal/CFF/**',
    ]
    core.resource_bundles = {
      'CloudPhoneRiskKit_Privacy' => [
        'RiskDetectorApp/Sources/CloudPhoneRiskKit/Resources/PrivacyInfo.xcprivacy',
      ]
    }
  end

  # ──────────────────────────────────────────────
  # Subspec: Full（含 CRiskCore C 自保护核心）
  # ──────────────────────────────────────────────
  s.subspec 'Full' do |full|
    full.dependency 'CloudPhoneRiskKit/Core'

    full.source_files = [
      'RiskDetectorApp/Sources/CRiskCore/**/*.{c,h}',
    ]
    full.public_header_files = [
      'RiskDetectorApp/Sources/CRiskCore/include/**/*.h',
    ]
    full.private_header_files = [
      'RiskDetectorApp/Sources/CRiskCore/*.h',
    ]

    full.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/RiskDetectorApp/Sources/CRiskCore/include"',
      'GCC_PREPROCESSOR_DEFINITIONS' => '$(inherited) CPRISK_COCOAPODS=1',
    }

    full.libraries = 'c++'
    full.frameworks = 'IOKit'
  end

  # 默认安装 Full（含 C 层加固）
  s.default_subspec = 'Full'
end
