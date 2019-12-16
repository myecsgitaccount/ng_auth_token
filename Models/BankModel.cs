using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace NG_Auth.Models
{
    public class BankModel
    {
        [Key]
        public int BankId { get; set; }
        public string BankName { get; set; }
    }
}
