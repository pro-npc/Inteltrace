import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

const outDir = join(process.cwd(), 'sample_data');
if (!existsSync(outDir)) {
  mkdirSync(outDir);
}

// 1. CDR (Call Detail Records)
const cdrContent = `date,time,call_type,caller_number,receiver_number,duration_sec,tower_id,tower_lat,tower_long
2024-03-15,08:55:00,call,+919876543210,+919988776655,54,BOM-ANW-2201,19.1351,72.8290
2024-03-15,23:41:00,call,+919876543210,+918877665544,302,GOA-PNJ-0091,15.4909,73.8278
2024-03-16,10:15:00,sms,+919876543210,+919988776655,0,BOM-ANW-2201,19.1351,72.8290`;

// 2. IPDR (IP Detail Records)
const ipdrContent = `session_start,session_end,device_id,imei,ip_address,domain_accessed,data_mb,location_lat,location_long
2024-03-15T11:05:00,2024-03-15T11:15:00,SAMSUNG_S23,35-XXXXXX-000001-7,45.32.87.211,wazirx.com,12.5,19.1351,72.8290
2024-03-15T23:25:00,2024-03-15T23:35:00,SAMSUNG_S23,35-XXXXXX-000001-7,45.32.87.211,instagram.com,45.2,15.5165,73.7668`;

// 3. Bank Statements
const bankContent = `date,time,transaction_type,cr_dr,amount,account_number,sender_name,receiver_name,sender_account,receiver_account,description,bank_name
2024-03-15,11:10:00,NEFT,CR,219450,HDFC-4821,WazirX_Exchange,Arjun Verma,WZX-9999,HDFC-4821,WAZIRX OTC LIQUIDATION,HDFC Bank
2024-03-15,11:18:00,IMPS,DR,15000,HDFC-4821,Arjun Verma,Rohan Sharma,HDFC-4821,AXIS-XXXXXXX-3312,KICKBACK TRANSFER,HDFC Bank
2024-03-16,09:00:00,RTGS,CR,500000,HDFC-4821,Unknown Entity,Arjun Verma,SG-TRX-11,HDFC-4821,INWARD REMITTANCE SINGAPORE,HDFC Bank`;

// 4. Social Media Report
const socialContent = `post_timestamp,platform,username,login_ip,device_used,location_tag,caption_keywords,tagged_accounts
2024-03-15T23:30:00,Instagram,@av_investments,45.32.87.211,SAMSUNG_S23,Candolim Goa,Night vibes 🌙 #goa,
2024-03-16T12:00:00,Twitter,@av_investments,45.32.87.211,SAMSUNG_S23,Mumbai,Back to the grind #hustle,@rohan_s`;

// 5. Crypto Wallet Info (Text file for copy-pasting)
const walletContent = `0x71C7656EC7ab88b098defB751B7401B5f6d8976F`;

writeFileSync(join(outDir, 'cdr_dump.csv'), cdrContent);
writeFileSync(join(outDir, 'ipdr_dump.csv'), ipdrContent);
writeFileSync(join(outDir, 'bank_statement.csv'), bankContent);
writeFileSync(join(outDir, 'social_report.csv'), socialContent);
writeFileSync(join(outDir, 'suspect_wallet.txt'), walletContent);

console.log('Sample files generated in ./sample_data/');
