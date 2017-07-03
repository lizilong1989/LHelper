Pod::Spec.new do |spec|
  spec.name         = 'LHelper'
  spec.version      = '1.0.0'
  spec.license      = 'MIT'
  spec.summary      = 'An Objective-C tool for IM'
  spec.homepage     = 'https://github.com/lizilong1989/LHelper'
  spec.author       = {'zilong.li' => '15131968@qq.com'}
  spec.source       =  {:git => 'https://github.com/lizilong1989/LHelper.git', :tag => spec.version.to_s }
  spec.source_files = "src/**/*.{h,m,mm,cpp,hpp}"
  spec.platform     = :ios, '6.0'
  spec.requires_arc = true
  spec.xcconfig     = {'OTHER_LDFLAGS' => '-ObjC'}
end
