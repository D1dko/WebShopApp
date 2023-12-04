﻿using System.ComponentModel.DataAnnotations;

namespace WebShopApp.Domain
{
    public class Brand
    {
        public int Id { get; set; }
        [Required]
        [MaxLength(30)]
        public string BrandName { get; set; }
        public virtual IEnumerable<Product> Products { get; set; } = new List<Product>();
    }
}
