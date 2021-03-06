//
//  ViewController.m
//  Demo
//
//  Created by EaseMob on 2017/7/7.
//  Copyright © 2017年 zilong.li. All rights reserved.
//

#import "ViewController.h"

#import "LEncryptHelper.h"

@interface ViewController ()

@property (nonatomic, strong) UITextField *textField;
@property (nonatomic, strong) UITextField *pwdField;
@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, strong) UIButton *aesBtn;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    [self.view addSubview:self.textField];
    [self.view addSubview:self.pwdField];
    [self.view addSubview:self.aesBtn];
    [self.view addSubview:self.textView];
}

#pragma mark - getter

- (UITextField *)textField
{
    if (_textField == nil) {
        _textField = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, CGRectGetWidth(self.view.frame), 50)];
        _textField.placeholder = @"输入加密字符串";
        _textField.layer.borderColor = [UIColor lightGrayColor].CGColor;
        _textField.layer.borderWidth = 0.5;
    }
    return _textField;
}

- (UITextField *)pwdField
{
    if (_pwdField == nil) {
        _pwdField = [[UITextField alloc] initWithFrame:CGRectMake(0, CGRectGetMaxY(_textField.frame) + 5, CGRectGetWidth(self.view.frame), 50)];
        _pwdField.placeholder = @"输入加密密钥";
        _pwdField.layer.borderColor = [UIColor lightGrayColor].CGColor;
        _pwdField.layer.borderWidth = 0.5;
    }
    return _pwdField;
}

- (UIButton *)aesBtn
{
    if (_aesBtn == nil) {
        _aesBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        _aesBtn.frame = CGRectMake(0, CGRectGetMaxY(_pwdField.frame) + 5, CGRectGetWidth(self.view.frame), 50);
        _aesBtn.backgroundColor = [UIColor purpleColor];
        [_aesBtn setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        [_aesBtn setTitle:@"AES加密" forState:UIControlStateNormal];
        [_aesBtn addTarget:self action:@selector(aesEncryptAction) forControlEvents:UIControlEventTouchUpInside];
    }
    return _aesBtn;
}

- (UITextView *)textView
{
    if (_textView == nil) {
        _textView = [[UITextView alloc] initWithFrame:CGRectMake(0, CGRectGetMaxY(_aesBtn.frame) + 5, CGRectGetWidth(self.view.frame), CGRectGetHeight(self.view.frame) - CGRectGetMaxY(_aesBtn.frame))];
        _textView.layer.borderColor = [UIColor lightGrayColor].CGColor;
        _textView.layer.borderWidth = 0.5;
    }
    return _textView;
}

#pragma mark - action

- (void)aesEncryptAction
{
    NSString *text = _textField.text;
    
    if (text.length == 0) {
        return;
    }
    
    if (_pwdField.text.length == 0) {
        return;
    }
    
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char iv[16] = {'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};
    
    //DES加密
    NSData *encryptData = [LEncryptHelper encryptWithData:data
                                                      key:[_pwdField.text dataUsingEncoding:NSUTF8StringEncoding].bytes
                                                       iv:[NSData dataWithBytes:iv length:16]
                                                     type:EMCrypt_aes128cbc];
    
    //DES解密
    NSData *decodeData = [LEncryptHelper decryptWithData:encryptData
                                                     key:[_pwdField.text dataUsingEncoding:NSUTF8StringEncoding].bytes
                                                      iv:[NSData dataWithBytes:iv length:16]
                                                    type:EMCrypt_aes128cbc];
    
    _textView.text = [NSString stringWithFormat:@"aes\ndata:%@\nencryptData:%@\ndecodeData:%@\n%@\n",data,encryptData,decodeData,[[NSString alloc] initWithData:decodeData encoding:NSUTF8StringEncoding]];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
