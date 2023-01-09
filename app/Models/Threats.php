<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Threats extends Model
{
    protected $fillable = [
        'hash',
        'list_id',
    ];
}
