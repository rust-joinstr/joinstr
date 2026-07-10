Pod::Spec.new do |s|
  s.name             = 'joinstr_flutter'
  s.version          = '0.1.0'
  s.summary          = 'Dart/Flutter bindings for the joinstr coinjoin library.'
  s.description      = <<-DESC
Dart/Flutter bindings for rust-joinstr/joinstr.
                       DESC
  s.homepage         = 'https://github.com/rust-joinstr/joinstr'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'joinstr' => 'email@example.com' }

  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  # Both were missing, unlike the macos podspec. Without the Flutter dependency
  # the pod cannot see the engine headers, and without a platform CocoaPods
  # falls back to a deployment target far below what Flutter requires. 13.0
  # matches the example's IPHONEOS_DEPLOYMENT_TARGET.
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  s.script_phase = {
    :name => 'Build Rust library',
    :script => 'sh "$PODS_TARGET_SRCROOT/../cargokit/build_pod.sh" ../rust joinstr_flutter',
    :execution_position => :before_compile,
    :input_files => ['${BUILT_PRODUCTS_DIR}/cargokit_phony'],
    :output_files => ["${BUILT_PRODUCTS_DIR}/libjoinstr_flutter.a"],
  }
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    # Flutter.framework does not contain a i386 slice.
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    'OTHER_LDFLAGS' => '-force_load ${BUILT_PRODUCTS_DIR}/libjoinstr_flutter.a',
  }
end
