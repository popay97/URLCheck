<?php

namespace App\Models;

// no more hashes model it is now threats model with fields hash , threat_type, platform_type, threat_entry_type, state
use Illuminate\Database\Eloquent\Model;

class Lists extends Model
{
    protected $fillable = [
        'threat_type',
        'platform_type',
        'threat_entry_type',
        'state',
    ];
}
