<?php

namespace Database\Seeders;

// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */

    public function run()
    {
        $threatTypes = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION', 'THREAT_TYPE_UNSPECIFIED'];
        $platformTypes = ['WINDOWS', 'LINUX', 'ANDROID', 'OSX', 'IOS', 'ANY_PLATFORM', 'ALL_PLATFORMS', 'CHROME', 'PLATFORM_TYPE_UNSPECIFIED'];
        $threatEntryTypes = ['URL', 'EXECUTABLE', 'THREAT_ENTRY_TYPE_UNSPECIFIED'];

        foreach ($threatTypes as $threatType) {
            foreach ($platformTypes as $platformType) {
                foreach ($threatEntryTypes as $threatEntryType) {
                    \App\Models\Lists::create([
                        'threat_type' => $threatType,
                        'platform_type' => $platformType,
                        'threat_entry_type' => $threatEntryType,
                        'state' => '',
                    ]);
                }
            }
        }
    }
}
