###########################################################################
# Template for Task 3 AWS AutoScaling Test                                #
# Do not edit the first section                                           #
# Only edit the second section to configure appropriate scaling policies  #
###########################################################################

############################
# FIRST SECTION BEGINS     #
# DO NOT EDIT THIS SECTION #
############################
locals {
  common_tags = {
    Project = "vm-scaling"
  }
  asg_tags = {
    key                 = "Project"
    value               = "vm-scaling"
    propagate_at_launch = true
  }
}

provider "aws" {
  region = "us-east-1"
}


resource "aws_security_group" "lg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "elb_asg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

######################
# FIRST SECTION ENDS #
######################

############################
# SECOND SECTION BEGINS    #
# PLEASE EDIT THIS SECTION #
############################

data "aws_vpc" "default" {
  default = true
}

data "aws_ami" "latest" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Step 1:
# TODO: Add missing values below
# ================================
resource "aws_launch_template" "lt" {
  name            = "lt-vm-scaling"
  image_id        = "ami-0e3d567ccafde16c5"
  instance_type   = "m5.large"

  monitoring {
    enabled = true
  }

  vpc_security_group_ids = [aws_security_group.elb_asg.id]

  tag_specifications {
    resource_type = "instance"
    tags = {
      Project = "vm-scaling"
    }
  }

  user_data = base64encode("#!/bin/bash\nyum install -y httpd\nsystemctl start httpd\necho 'OK' > /var/www/html/index.html")
}

# Create an auto scaling group with appropriate parameters
# TODO: fill the missing values per the placeholders
resource "aws_autoscaling_group" "asg" {
  availability_zones        = ["us-east-1a", "us-east-1b"]
  max_size                  = 2
  min_size                  = 1
  desired_capacity          = 1
  default_cooldown          = 300
  health_check_grace_period = 300
  health_check_type         = "ELB"
  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
  target_group_arns         = [aws_lb_target_group.tg.arn]
  tag {
    key                 = local.asg_tags.key
    value               = local.asg_tags.value
    propagate_at_launch = local.asg_tags.propagate_at_launch
  }
}

# TODO: Create a Load Generator AWS instance with proper tags
 #tags                   = { Project = "vm-scaling", Name = "LoadGenerator" }
resource "aws_instance" "load_generator" {
  ami                    = "ami-0469ff4742c562d63"
  instance_type          = "m5.large"
  tags                   = local.common_tags
  vpc_security_group_ids = [aws_security_group.lg.id]
  subnet_id              = aws_subnet.alb_sub1.id
}

# Step 2:
# TODO: Create an Application Load Balancer with appropriate listeners and target groups
# The lb_listener documentation demonstrates how to connect these resources
# Create and attach your subnet to the Application Load Balancer 

resource "aws_subnet" "alb_sub1" {
  vpc_id            = data.aws_vpc.default.id
  cidr_block        = "172.31.250.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "alb_sub2" {
  vpc_id            = data.aws_vpc.default.id
  cidr_block        = "172.31.251.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_lb" "alb" {
  name               = "vm-scaling-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.elb_asg.id]
  subnets            = [aws_subnet.alb_sub1.id, aws_subnet.alb_sub2.id]
  tags               = local.common_tags
}

resource "aws_lb_target_group" "tg" {
  name     = "vm-scaling-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id
}

resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# Step 3:
# TODO: Create 2 policies: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_policy

resource "aws_autoscaling_policy" "scale_out" {
  name                   = "scale-out"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

resource "aws_autoscaling_policy" "scale_in" {
  name                   = "scale-in"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

# Step 4:
# TODO: Create 2 cloudwatch alarms: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# Don't forget to trigger the appropriate policy you created above when alarm is raised
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "70"
  alarm_actions       = [aws_autoscaling_policy.scale_out.arn]
  dimensions          = { AutoScalingGroupName = aws_autoscaling_group.asg.name }
}

resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "low-cpu"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "30"
  alarm_actions       = [aws_autoscaling_policy.scale_in.arn]
  dimensions          = { AutoScalingGroupName = aws_autoscaling_group.asg.name }
}

######################################
# SECOND SECTION ENDS                #
# MAKE SURE YOU COMPLETE ALL 4 STEPS #
######################################