<?php

namespace App\Console\Commands;

use App\Jobs\FetchListUpdates;
use Illuminate\Console\Command;
use App\Models\Threats;
use App\Models\Lists;
use COM;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Config;

class hashFiller extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hashes:filler';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    /**
     * Execute the console command.
     *
     * @return int
     */

    function fullUpdate($response, $list)
    {
        error_log('full update');
        //find all entries in threats with list_id = $list->id and delete them
        Threats::where('list_id', $list->id)->delete();
        $state = $response['newClientState'];
        Lists::where('id', $list->id)->update(['state' => $state]);
        foreach ($response['additions'] as $addition) {
            $prefixSize = $addition['rawHashes']['prefixSize'];
            $rawHashes = $addition['rawHashes']['rawHashes'];
            $decodedHashes = base64_decode($rawHashes);
            $hashes = [];
            for ($i = 0; $i < strlen($decodedHashes); $i += $prefixSize) {
                $hash = substr($decodedHashes, $i, $prefixSize);
                $hashes[] = bin2hex($hash);
            }
            foreach ($hashes as $hash) {
                Threats::create([
                    'hash' => $hash,
                    'list_id' => $list->id,
                ]);
            }
        }
    }
    function partialUpdate($response, $list)
    {
        error_log('partial update');
        //first check if key 'removals' and 'additions' exist in $response, if none exist then return status: 'no updates'
        if (!array_key_exists('removals', $response) && !array_key_exists('additions', $response)) {
            error_log('no updates');
            return 'no updates';
        }
        //if removals exist we should perform those first
        if (array_key_exists('removals', $response)) {
            //get all hashes for the list
            $hashes = Threats::where('list_id', $list->id)->get();
            //verify that the hashes are lexicographically sorted
            $sorted = true;
            for ($i = 0; $i < count($hashes) - 1; $i++) {
                if ($hashes[$i]->hash > $hashes[$i + 1]->hash) {
                    $sorted = false;
                    break;
                }
            }
            //if hashes are not sorted then sort them lexicographically
            if (!$sorted) {
                $hashes = $hashes->sortBy('hash');
            }
            //get all removals
            foreach ($response['removals'] as $removal) {
                $rawIndices = $removal['rawIndices']['indices'];
                //rawIndices is array of integers, each integer is the index of the hash to be removed
                //remove all entries from $hashes with index in $rawIndices
                foreach ($rawIndices as $index) {
                    //delete all entries from threats with id = $hashes[$index]->id
                    Threats::where('id', $hashes[$index]->id)->delete();
                }
            }
        }
        //if additions exist we should perform those
        if (array_key_exists('additions', $response)) {
            foreach ($response['additions'] as $addition) {
                $prefixSize = $addition['rawHashes']['prefixSize'];
                $rawHashes = $addition['rawHashes']['rawHashes'];
                $decodedHashes = base64_decode($rawHashes);
                $hashes = [];
                for ($i = 0; $i < strlen($decodedHashes); $i += $prefixSize) {
                    $hash = substr($decodedHashes, $i, $prefixSize);
                    $hashes[] = bin2hex($hash);
                }
                foreach ($hashes as $hash) {
                    Threats::create([
                        'hash' => $hash,
                        'list_id' => $list->id,
                    ]);
                }
            }
        }
        $state = $response['newClientState'];
        Lists::where('id', $list->id)->update(['state' => $state]);
    }
    function fetchThreatListUpdates()
    {
        $regions = ['AF', 'AX', 'AL', 'DZ', 'AS', 'AD', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', ' AZ', 'BS', 'BH', 'BD', 'BB', 'BY', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BQ', 'BA', 'BW', 'BV', 'BR', 'IO', 'BN', 'BG', 'BF', 'BI', 'KH', 'CM', 'CA', 'CV', 'KY', 'CF', 'TD', 'CL', 'CN', 'CX', 'CC', 'CO', 'KM', 'CG', 'CD', 'CK', 'CR', 'CI', 'HR', 'CU', 'CW', 'CY', 'CZ', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GF', 'PF', 'TF', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GP', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'VA', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IR', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'KP', 'KR', 'KW', 'KG', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MO', 'MK', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MQ', 'MR', 'MU', 'YT', 'MX', 'FM', 'MD', 'MC', 'MN', 'ME', 'MS', 'MA', 'MZ', 'MM', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'RW', 'BL', 'SH', 'KN', 'LC', 'MF', 'PM', 'VC', 'WS', 'SM', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SX', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'SS', 'ES', 'LK', 'SD', 'SR', 'SJ', 'SZ', 'SE', 'CH', 'SY', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'AE', 'GB', 'US', 'UM', 'UY', 'UZ', 'VU', 'VE', 'VN', 'VG', 'VI', 'WF', 'EH', 'YE', 'ZM', 'ZW'];
        $lists = Lists::all();
        $minWaitDuration = 0;
        $loopState = [];
        Config::set('global.dbUpdateInProgress', 1);
        for ($i = 0; $i < count($lists); $i++) {
            for ($j = 0; $j < count($regions); $j++) {
                $response = Http::withHeaders([
                    'Content-Type' => 'application/json'
                ])->post('https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key=' . config('global.google_api_key'), [
                    'client' => [
                        'clientId' => 'urlcheck',
                        'clientVersion' => '1.0.0'
                    ],
                    'listUpdateRequests' => [
                        'threatType' => $lists[$i]->threat_type,
                        'platformType' => $lists[$i]->platform_type,
                        'threatEntryType' => $lists[$i]->threat_entry_type,
                        'state' =>  $lists[$i]->state,
                        'constraints' => [
                            'maxUpdateEntries' => 100,
                            'maxDatabaseEntries' => 10000,
                            'region' => $regions[$j],
                            'supportedCompressions' => ['RAW']
                        ]
                    ]
                ]);
                //save the i and j to varable called a loopState, if a wait duration is issues by api, we need to schedule a job to continue from the loopState
                $loopState = [
                    'i' => $i,
                    'j' => $j
                ];
                $data = json_decode($response->body(), true);
                if (!array_key_exists('listUpdateResponses', $data)) {
                    error_log('no listUpdateResponses');
                    continue;
                }
                $responseType = $data['listUpdateResponses'][0]['responseType'];
                $minWaitDuration = $data['minimumWaitDuration'];
                error_log($minWaitDuration);
                if ($responseType == 'FULL_UPDATE') {
                    $this->fullUpdate($data['listUpdateResponses'][0], $lists[$i]);
                } else if ($responseType == 'PARTIAL_UPDATE') {
                    $this->partialUpdate($data['listUpdateResponses'][0], $lists[$i]);
                }
                if ($minWaitDuration != null && $minWaitDuration != '') {
                    $minWaitDuration = substr($data['minimumWaitDuration'], 0, -1);
                    $minWaitDuration = (int)$minWaitDuration;
                } else {
                    $minWaitDuration = 0;
                }
            }
            if ($minWaitDuration > 0) {
                FetchListUpdates::dispatch($loopState, $minWaitDuration);
            }
        }
        //check if loopState indices are at the end of the array, if so, set dbUpdateInProgress to false
        if ($loopState['i'] == count($lists) - 1 && $loopState['j'] == count($regions) - 1) {
            Config::set('global.dbUpdateInProgress', 0);
            error_log(Config::get('global.dbUpdateInProgress'));
        }
    }
    public function handle()
    {
        $this->fetchThreatListUpdates();
    }
}
