<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use App\Models\User;

class Role extends Model
{
    use HasFactory;
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [

        'type_of_user',
    ];
    public function user()
    {
        return $this->hasMany(User::class);
        // return $this->hasOne(User::class, 'role_id');
    }
}
